//! Windows transfer paths stay pinned by handles while privileged operations run.
//! Reparse points are rejected at every component; source ownership also rejects
//! hardlinks to another account's files. The engine journal is never user writable.
use super::*;
use fips_file_transfer::{Destination, ManifestFile};
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::mem::{offset_of, size_of, size_of_val};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::{ERROR_NO_TOKEN, GetLastError, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Threading::*;

fn checked(ok: i32) -> Result<()> {
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
fn raw(file: &File) -> HANDLE {
    file.as_raw_handle()
}
fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn sid_string(sid: PSID) -> Result<String> {
    let mut value = null_mut();
    unsafe {
        checked(ConvertSidToStringSidW(sid, &mut value))?;
        let _allocation = Local(value.cast());
        let mut length = 0;
        while *value.add(length) != 0 {
            length += 1;
        }
        Ok(String::from_utf16(std::slice::from_raw_parts(
            value, length,
        ))?)
    }
}
fn security(file: &File) -> Result<(Local, PSID, *mut ACL)> {
    let mut descriptor = null_mut();
    let mut owner = null_mut();
    let mut acl = null_mut();
    let error = unsafe {
        GetSecurityInfo(
            raw(file),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    ensure!(error == 0, "Could not inspect file permissions: {error}");
    let descriptor = Local(descriptor);
    ensure!(
        !owner.is_null() && !acl.is_null(),
        "File permissions are missing"
    );
    Ok((descriptor, owner, acl))
}
fn owner(file: &File) -> Result<String> {
    let (_descriptor, sid, _) = security(file)?;
    sid_string(sid)
}
fn verify_user(file: &File, expected: &str) -> Result<()> {
    let (_descriptor, sid, acl) = security(file)?;
    ensure!(sid_string(sid)? == expected, "File belongs to another user");
    let mut info = ACL_SIZE_INFORMATION::default();
    unsafe {
        checked(GetAclInformation(
            acl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            size_of_val(&info) as u32,
            AclSizeInformation,
        ))?;
        for index in 0..info.AceCount {
            let mut pointer = null_mut();
            checked(GetAce(acl, index, &mut pointer))?;
            let header = &*pointer.cast::<ACE_HEADER>();
            if header.AceFlags & 8 != 0 || header.AceType == 1 {
                continue;
            }
            ensure!(header.AceType == 0, "Unsupported file transfer permission");
            let ace = &*pointer.cast::<ACCESS_ALLOWED_ACE>();
            let sid = sid_string((&ace.SidStart as *const u32).cast_mut().cast())?;
            let write = DELETE
                | WRITE_DAC
                | WRITE_OWNER
                | FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_DELETE_CHILD
                | FILE_WRITE_ATTRIBUTES
                | FILE_WRITE_EA
                | 0x10000000
                | 0x40000000;
            ensure!(
                sid == expected || trusted(&sid) || ace.Mask & write == 0,
                "File transfer storage is writable by another user"
            );
        }
    }
    Ok(())
}
fn process_token(access: u32) -> Result<OwnedHandle> {
    let mut handle = null_mut();
    unsafe {
        checked(OpenProcessToken(GetCurrentProcess(), access, &mut handle))?;
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}
fn is_system() -> Result<bool> {
    let token = process_token(TOKEN_QUERY)?;
    let mut storage = [0usize; 128];
    let mut needed = 0;
    unsafe {
        checked(GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            storage.as_mut_ptr().cast(),
            size_of_val(&storage) as u32,
            &mut needed,
        ))?;
        let user = &*(storage.as_ptr().cast::<TOKEN_USER>());
        Ok(IsWellKnownSid(user.User.Sid, WinLocalSystemSid) != 0)
    }
}

// Enable ownership assignment only on this synchronous operation's thread.
// Never leave SeRestorePrivilege enabled in the process-wide service token.
struct RestorePrivilege {
    previous: Option<OwnedHandle>,
    _token: OwnedHandle,
}
impl RestorePrivilege {
    fn enter() -> Result<Option<Self>> {
        if !is_system()? {
            return Ok(None);
        }
        let mut previous = null_mut();
        let previous = unsafe {
            if OpenThreadToken(
                GetCurrentThread(),
                TOKEN_IMPERSONATE | TOKEN_QUERY,
                1,
                &mut previous,
            ) != 0
            {
                Some(OwnedHandle::from_raw_handle(previous))
            } else {
                ensure!(
                    GetLastError() == ERROR_NO_TOKEN,
                    "Could not preserve thread identity"
                );
                None
            }
        };
        let process = process_token(TOKEN_DUPLICATE | TOKEN_QUERY)?;
        let mut token = null_mut();
        unsafe {
            checked(DuplicateTokenEx(
                process.as_raw_handle(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_IMPERSONATE,
                null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut token,
            ))?;
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut privileges = TOKEN_PRIVILEGES::default();
        privileges.PrivilegeCount = 1;
        unsafe {
            checked(LookupPrivilegeValueW(
                null(),
                SE_RESTORE_NAME,
                &mut privileges.Privileges[0].Luid,
            ))?;
            privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            checked(AdjustTokenPrivileges(
                token.as_raw_handle(),
                0,
                &privileges,
                0,
                null_mut(),
                null_mut(),
            ))?;
            ensure!(
                GetLastError() == 0,
                "File ownership privilege is unavailable"
            );
            checked(SetThreadToken(null(), token.as_raw_handle()))?;
        }
        Ok(Some(Self {
            previous,
            _token: token,
        }))
    }
}
impl Drop for RestorePrivilege {
    fn drop(&mut self) {
        let previous = self
            .previous
            .as_ref()
            .map_or(null_mut(), AsRawHandle::as_raw_handle);
        if unsafe { SetThreadToken(null(), previous) } == 0 {
            // Continuing would leak an elevated thread token into unrelated work.
            std::process::abort();
        }
    }
}

fn descriptor(owner: &str) -> Result<Local> {
    let sddl = format!("O:{owner}D:P(A;OICI;FA;;;{owner})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    let encoded: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut value = null_mut();
    unsafe {
        checked(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            encoded.as_ptr(),
            1,
            &mut value,
            null_mut(),
        ))?;
    }
    Ok(Local(value))
}
fn apply_owner(file: &File, expected: &str) -> Result<()> {
    let descriptor = descriptor(expected)?;
    let mut sid = null_mut();
    let mut acl = null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    let _restore = RestorePrivilege::enter()?;
    unsafe {
        checked(GetSecurityDescriptorOwner(
            descriptor.0,
            &mut sid,
            &mut defaulted,
        ))?;
        checked(GetSecurityDescriptorDacl(
            descriptor.0,
            &mut present,
            &mut acl,
            &mut defaulted,
        ))?;
        ensure!(
            present != 0 && !acl.is_null(),
            "File permissions are missing"
        );
        let error = SetSecurityInfo(
            raw(file),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            sid,
            null_mut(),
            acl,
            null(),
        );
        ensure!(error == 0, "Could not assign file ownership: {error}");
    }
    Ok(())
}
fn open_handle(path: &Path, access: u32, directory: bool) -> Result<File> {
    let file = OpenOptions::new()
        .access_mode(access)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
        )
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "Reparse points are not allowed in file transfers"
    );
    ensure!(
        if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        },
        "Unexpected file transfer path type"
    );
    Ok(file)
}
struct Guards {
    paths: Vec<PathBuf>,
    handles: Vec<File>,
}
fn lock_directories(path: &Path) -> Result<Guards> {
    let absolute = std::path::absolute(path)?;
    let mut current = PathBuf::new();
    let mut guards = Guards {
        paths: Vec::new(),
        handles: Vec::new(),
    };
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => {
                ensure!(
                    matches!(
                        prefix.kind(),
                        std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)
                    ),
                    "File transfers require local storage"
                );
                current.push(component);
                continue;
            }
            Component::RootDir | Component::Normal(_) => current.push(component),
            _ => anyhow::bail!("Invalid file transfer path"),
        }
        guards.handles.push(open_handle(
            &current,
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            true,
        )?);
        guards.paths.push(current.clone());
    }
    ensure!(!guards.handles.is_empty(), "Missing storage directory");
    Ok(guards)
}
fn expected_owner(config: &Path) -> Result<String> {
    let guards = lock_directories(config.parent().context("Missing config directory")?)?;
    owner(guards.handles.last().unwrap())
}
fn check_app_directories(config: &Path, guards: &Guards, expected: &str) -> Result<()> {
    let parent = std::path::absolute(config.parent().context("Missing config directory")?)?;
    for (path, file) in guards.paths.iter().zip(&guards.handles) {
        if path.starts_with(&parent) {
            verify_user(file, expected)?;
        }
    }
    Ok(())
}
fn create_directory(path: &Path, expected: &str) -> Result<()> {
    let descriptor = descriptor(expected)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let _restore = RestorePrivilege::enter()?;
    unsafe { checked(CreateDirectoryW(wide(path).as_ptr(), &attributes)) }
}
fn create_file(path: &Path, expected: &str) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .access_mode(0xC0000000 | READ_CONTROL | WRITE_DAC | WRITE_OWNER | DELETE)
        .share_mode(FILE_SHARE_READ)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "Expected a regular transfer file"
    );
    // The exclusive handle prevents replacement while permissions are assigned.
    if let Err(error) = apply_owner(&file, expected) {
        let _ = delete_handle(&file);
        return Err(error);
    }
    Ok(file)
}
pub(super) fn owned_dir(config: &Path, path: &Path) -> Result<()> {
    let expected = expected_owner(config)?;
    let guards = lock_directories(path.parent().context("Missing storage parent")?)?;
    check_app_directories(config, &guards, &expected)?;
    match create_directory(path, &expected) {
        Ok(()) => {}
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists) => {}
        Err(error) => return Err(error),
    }
    let directory = open_handle(path, READ_CONTROL | FILE_READ_ATTRIBUTES, true)?;
    verify_user(&directory, &expected)?;
    Ok(())
}
pub(super) fn open_owned(config: &Path, path: &Path) -> Result<File> {
    let expected = expected_owner(config)?;
    let guards = lock_directories(path.parent().context("Missing file parent")?)?;
    check_app_directories(config, &guards, &expected)?;
    let file = open_handle(path, 0x80000000 | READ_CONTROL, false)?;
    verify_user(&file, &expected)?;
    Ok(file)
}
pub(super) fn visit_names(
    config: &Path,
    path: &Path,
    mut visitor: impl FnMut(&std::ffi::OsStr),
) -> Result<()> {
    let expected = expected_owner(config)?;
    let guards = lock_directories(path)?;
    check_app_directories(config, &guards, &expected)?;
    // These handles deny deletion/rename for every ancestor through enumeration.
    for entry in fs::read_dir(path)? {
        visitor(&entry?.file_name());
    }
    drop(guards);
    Ok(())
}
pub(super) fn create_owned(config: &Path, path: &Path) -> Result<File> {
    let expected = expected_owner(config)?;
    let guards = lock_directories(path.parent().context("Missing file parent")?)?;
    check_app_directories(config, &guards, &expected)?;
    create_file(path, &expected)
}
fn delete_handle(file: &File) -> Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        checked(SetFileInformationByHandle(
            raw(file),
            FileDispositionInfo,
            (&info as *const FILE_DISPOSITION_INFO).cast(),
            size_of_val(&info) as u32,
        ))
    }
}
pub(super) fn remove(path: &Path, directory: bool) -> Result<()> {
    let _guards = lock_directories(path.parent().context("Missing file parent")?)?;
    let file = open_handle(
        path,
        DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES,
        directory,
    )?;
    delete_handle(&file)
}
pub(super) fn write_atomic(config: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    let expected = expected_owner(config)?;
    let guards = lock_directories(path.parent().context("Missing file parent")?)?;
    check_app_directories(config, &guards, &expected)?;
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4().simple()));
    let mut file = create_file(&temporary, &expected)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        let name: Vec<u16> = path.as_os_str().encode_wide().collect();
        let size = offset_of!(FILE_RENAME_INFO, FileName) + name.len() * 2;
        let mut storage = vec![0usize; size.div_ceil(size_of::<usize>())];
        unsafe {
            let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
            (*info).Anonymous.ReplaceIfExists = true;
            (*info).RootDirectory = null_mut();
            (*info).FileNameLength = (name.len() * 2) as u32;
            std::ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());
            checked(SetFileInformationByHandle(
                raw(&file),
                FileRenameInfo,
                info.cast(),
                size as u32,
            ))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = delete_handle(&file);
    }
    result
}

fn trusted(sid: &str) -> bool {
    matches!(
        sid,
        "S-1-5-18"
            | "S-1-5-32-544"
            | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    )
}
fn verify_private(file: &File, strict: bool) -> Result<()> {
    let (descriptor, sid, acl) = security(file)?;
    ensure!(
        trusted(&sid_string(sid)?),
        "Service storage has an untrusted owner"
    );
    let mut info = ACL_SIZE_INFORMATION::default();
    unsafe {
        if strict {
            let mut control = 0;
            let mut revision = 0;
            checked(GetSecurityDescriptorControl(
                descriptor.0,
                &mut control,
                &mut revision,
            ))?;
            ensure!(
                control & SE_DACL_PROTECTED != 0,
                "Service storage inherits permissions"
            );
        }
        checked(GetAclInformation(
            acl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            size_of_val(&info) as u32,
            AclSizeInformation,
        ))?;
        for index in 0..info.AceCount {
            let mut pointer = null_mut();
            checked(GetAce(acl, index, &mut pointer))?;
            let header = &*pointer.cast::<ACE_HEADER>();
            if header.AceFlags & 8 != 0 {
                continue;
            } // Inherit-only ACE does not apply here.
            ensure!(
                header.AceType == 0 || (!strict && header.AceType == 1),
                "Unsupported service storage permission"
            );
            if header.AceType == 1 {
                continue;
            }
            let ace = &*pointer.cast::<ACCESS_ALLOWED_ACE>();
            let sid = sid_string((&ace.SidStart as *const u32).cast_mut().cast())?;
            let unsafe_rights = if strict {
                u32::MAX
            } else {
                DELETE
                    | WRITE_DAC
                    | WRITE_OWNER
                    | FILE_DELETE_CHILD
                    | FILE_WRITE_ATTRIBUTES
                    | FILE_WRITE_EA
                    | 0x10000000
                    | 0x40000000
            };
            ensure!(
                trusted(&sid) || ace.Mask & unsafe_rights == 0,
                "Service storage is writable by another user"
            );
        }
    }
    Ok(())
}
pub(super) fn private_store(config: &Path) -> Result<PathBuf> {
    if !is_system()? {
        owned_dir(config, &state_dir(config))?;
        let root = state_dir(config).join("engine");
        owned_dir(config, &root)?;
        return Ok(root);
    }
    let mut pointer = null_mut();
    let base = unsafe {
        let result = windows_sys::Win32::UI::Shell::SHGetKnownFolderPath(
            &windows_sys::Win32::UI::Shell::FOLDERID_ProgramData,
            0,
            null_mut(),
            &mut pointer,
        );
        ensure!(
            result >= 0 && !pointer.is_null(),
            "Service storage location is unavailable"
        );
        let mut length = 0;
        while *pointer.add(length) != 0 {
            length += 1;
        }
        let path = PathBuf::from(std::ffi::OsString::from_wide(std::slice::from_raw_parts(
            pointer, length,
        )));
        windows_sys::Win32::System::Com::CoTaskMemFree(pointer.cast());
        path
    };
    let mut guards = lock_directories(&base)?;
    for directory in &guards.handles {
        verify_private(directory, false)?;
    }
    let canonical = fs::canonicalize(config)?;
    let bytes: Vec<u8> = canonical
        .as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect();
    let digest = format!("{:x}", Sha256::digest(bytes));
    let mut root = base;
    for name in ["nvpn-file-transfer-service", digest.as_str()] {
        root.push(name);
        match create_directory(&root, "S-1-5-18") {
            Ok(()) => {}
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) => {}
            Err(error) => return Err(error),
        }
        let directory = open_handle(&root, READ_CONTROL | FILE_READ_ATTRIBUTES, true)?;
        verify_private(&directory, true)?;
        guards.handles.push(directory);
    }
    Ok(root)
}

pub(super) fn destination(config: &Path) -> Arc<dyn Destination> {
    Arc::new(InboxDestination {
        config: config.to_owned(),
        export: Mutex::new(None),
    })
}
struct InboxDestination {
    config: PathBuf,
    export: Mutex<Option<Export>>,
}
struct Export {
    _guards: Guards,
    directory: File,
    files: Vec<File>,
    manifests: Vec<ManifestFile>,
    paths: Vec<String>,
    expected: String,
    committed: bool,
}
impl Drop for Export {
    fn drop(&mut self) {
        if !self.committed {
            for file in self.files.drain(..) {
                let _ = delete_handle(&file);
            }
            let _ = delete_handle(&self.directory);
        }
    }
}
impl InboxDestination {
    fn prepare_export(&self, id: &str, manifests: Vec<ManifestFile>) -> Result<Export> {
        ensure!(
            valid_id(id) && !manifests.is_empty() && manifests.len() <= 32,
            "Invalid file transfer"
        );
        ensure!(
            manifests.iter().all(
                |file| fips_file_transfer::wire::valid_filename(&file.filename)
                    && file.size_bytes <= MAX_FILE_BYTES
            ),
            "Invalid transfer file"
        );
        let expected = expected_owner(&self.config)?;
        let inbox = state_dir(&self.config).join("inbox");
        owned_dir(&self.config, &inbox)?;
        let guards = lock_directories(&inbox)?;
        check_app_directories(&self.config, &guards, &expected)?;
        // A fresh export never replaces a previous completed or interrupted one.
        let batch = inbox.join(format!("{id}-{}", uuid::Uuid::new_v4().simple()));
        let initial_owner = if is_system()? {
            "S-1-5-18".to_owned()
        } else {
            expected.clone()
        };
        create_directory(&batch, &initial_owner)?;
        let directory = open_handle(
            &batch,
            READ_CONTROL | FILE_READ_ATTRIBUTES | WRITE_DAC | WRITE_OWNER | DELETE,
            true,
        )?;
        ensure!(
            owner(&directory)? == initial_owner,
            "Export directory owner changed"
        );
        let mut export = Export {
            _guards: guards,
            directory,
            files: Vec::new(),
            manifests,
            paths: Vec::new(),
            expected,
            committed: false,
        };
        for name in export_names(&export.manifests) {
            let path = batch.join(name);
            export.files.push(create_file(&path, &initial_owner)?);
            export.paths.push(path.to_string_lossy().into_owned());
        }
        Ok(export)
    }
}
impl Destination for InboxDestination {
    fn prepare(&self, id: String, files: Vec<ManifestFile>) -> fips_file_transfer::Result<()> {
        let export = self
            .prepare_export(&id, files)
            .map_err(|error| error.to_string())?;
        *self.export.lock().map_err(|_| "File export unavailable")? = Some(export);
        Ok(())
    }
    fn write(&self, index: u32, bytes: Vec<u8>) -> fips_file_transfer::Result<()> {
        let mut state = self.export.lock().map_err(|_| "File export unavailable")?;
        let export = state.as_mut().ok_or("File export not prepared")?;
        if export.committed {
            return Ok(());
        }
        export
            .files
            .get_mut(index as usize)
            .ok_or("Invalid file index")?
            .write_all(&bytes)
            .map_err(|error| error.to_string())
    }
    fn finish_file(&self, index: u32) -> fips_file_transfer::Result<()> {
        let state = self.export.lock().map_err(|_| "File export unavailable")?;
        let export = state.as_ref().ok_or("File export not prepared")?;
        if export.committed {
            return Ok(());
        }
        let file = export
            .files
            .get(index as usize)
            .ok_or("Invalid file index")?;
        let expected = export
            .manifests
            .get(index as usize)
            .ok_or("Invalid file index")?
            .size_bytes;
        if file.metadata().map_err(|e| e.to_string())?.len() != expected {
            return Err("Exported file has the wrong size".into());
        }
        file.sync_all().map_err(|error| error.to_string())
    }
    fn commit(&self) -> fips_file_transfer::Result<Vec<String>> {
        let mut state = self.export.lock().map_err(|_| "File export unavailable")?;
        let export = state.as_mut().ok_or("File export not prepared")?;
        if !export.committed {
            for file in &export.files {
                apply_owner(file, &export.expected).map_err(|error| error.to_string())?;
            }
            apply_owner(&export.directory, &export.expected).map_err(|error| error.to_string())?;
            export.files.clear();
            export.committed = true;
        }
        Ok(export.paths.clone())
    }
    fn abort(&self) {
        if let Ok(mut state) = self.export.lock() {
            state.take();
        }
    }
}
