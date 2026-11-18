use super::*;
use fips_file_transfer::{Destination, ManifestFile};
use rustix::fs::{AtFlags, Mode, OFlags, mkdirat, openat, unlinkat};
use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;
use std::sync::Mutex;

pub(super) struct InboxDestination {
    config: PathBuf,
    state: Mutex<Option<Export>>,
}
struct Export {
    inbox: File,
    batch: String,
    directory: File,
    files: Vec<File>,
    manifests: Vec<ManifestFile>,
    names: Vec<String>,
    paths: Vec<String>,
    committed: bool,
}
impl Drop for Export {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for name in self.names.iter().take(self.files.len()) {
            let _ = unlinkat(&self.directory, name.as_str(), AtFlags::empty());
        }
        let current = openat(
            &self.inbox,
            self.batch.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        );
        if let (Ok(current), Ok(expected)) = (current, self.directory.metadata()) {
            if File::from(current).metadata().is_ok_and(|actual| {
                actual.dev() == expected.dev() && actual.ino() == expected.ino()
            }) {
                let _ = unlinkat(&self.inbox, self.batch.as_str(), AtFlags::REMOVEDIR);
            }
        }
    }
}
impl InboxDestination {
    pub(super) fn new(config: &Path) -> Self {
        Self {
            config: config.to_owned(),
            state: Mutex::new(None),
        }
    }

    fn prepare_export(&self, id: &str, manifests: Vec<ManifestFile>) -> Result<Export> {
        ensure!(
            valid_id(id) && !manifests.is_empty() && manifests.len() <= 32,
            "Invalid transfer"
        );
        for manifest in &manifests {
            ensure!(
                fips_file_transfer::wire::valid_filename(&manifest.filename),
                "Invalid filename"
            );
        }
        let inbox_path = state_dir(&self.config).join("inbox");
        let inbox = unix_storage::directory(&inbox_path)?;
        check_owner(&self.config, &inbox.metadata()?)?;
        let mut batch = id.to_owned();
        match mkdirat(&inbox, &batch, Mode::from_raw_mode(0o700)) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {
                // A crash after export but before its receipt must reuse the
                // exact completed files. Never overwrite an existing export.
                if let Ok(export) =
                    existing_export(&self.config, &inbox, &inbox_path, id, &manifests)
                {
                    return Ok(export);
                }
                batch = format!("{id}-{}", uuid::Uuid::new_v4().simple());
                mkdirat(&inbox, &batch, Mode::from_raw_mode(0o700))?;
            }
            Err(error) => return Err(error.into()),
        }
        let directory = File::from(openat(
            &inbox,
            &batch,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        // Keep root ownership until every byte has been verified and exported.
        // All operations below are relative to the held directory descriptor.
        let mut export = Export {
            inbox,
            batch: batch.clone(),
            directory,
            files: Vec::new(),
            names: export_names(&manifests),
            manifests,
            paths: Vec::new(),
            committed: false,
        };
        for name in &export.names {
            export.files.push(File::from(openat(
                &export.directory,
                name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?));
            export.paths.push(
                inbox_path
                    .join(&batch)
                    .join(name)
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        Ok(export)
    }
}

fn existing_export(
    config: &Path,
    inbox: &File,
    path: &Path,
    id: &str,
    manifests: &[ManifestFile],
) -> Result<Export> {
    let directory = File::from(openat(
        inbox,
        id,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    check_owner(config, &directory.metadata()?)?;
    let mut paths = Vec::new();
    let names = export_names(manifests);
    for (manifest, name) in manifests.iter().zip(&names) {
        let mut file = File::from(openat(
            &directory,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        check_owner(config, &metadata)?;
        ensure!(
            metadata.is_file() && metadata.len() == manifest.size_bytes,
            "Existing file differs"
        );
        let mut hash = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        let mut count = 0;
        loop {
            let length = file.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            count += length as u64;
            ensure!(count <= manifest.size_bytes, "Existing file changed");
            hash.update(&buffer[..length]);
        }
        ensure!(
            count == manifest.size_bytes && format!("{:x}", hash.finalize()) == manifest.sha256,
            "Existing file differs"
        );
        paths.push(path.join(id).join(name).to_string_lossy().into_owned());
    }
    Ok(Export {
        inbox: inbox.try_clone()?,
        batch: id.to_owned(),
        directory,
        files: Vec::new(),
        manifests: manifests.to_vec(),
        names,
        paths,
        committed: true,
    })
}

impl Destination for InboxDestination {
    fn prepare(&self, id: String, files: Vec<ManifestFile>) -> fips_file_transfer::Result<()> {
        let export = self
            .prepare_export(&id, files)
            .map_err(|error| error.to_string())?;
        *self.state.lock().map_err(|_| "File export unavailable")? = Some(export);
        Ok(())
    }
    fn write(&self, index: u32, bytes: Vec<u8>) -> fips_file_transfer::Result<()> {
        let mut state = self.state.lock().map_err(|_| "File export unavailable")?;
        let export = state.as_mut().ok_or("File export not prepared")?;
        if !export.committed {
            let file = export
                .files
                .get_mut(index as usize)
                .ok_or("Invalid file index")?;
            file.write_all(&bytes).map_err(|error| error.to_string())?;
        }
        Ok(())
    }
    fn finish_file(&self, index: u32) -> fips_file_transfer::Result<()> {
        let state = self.state.lock().map_err(|_| "File export unavailable")?;
        let export = state.as_ref().ok_or("File export not prepared")?;
        if !export.committed {
            let file = export
                .files
                .get(index as usize)
                .ok_or("Invalid file index")?;
            if file.metadata().map_err(|e| e.to_string())?.len()
                != export.manifests[index as usize].size_bytes
            {
                return Err("Exported file has the wrong size".into());
            }
            file.sync_all().map_err(|error| error.to_string())?;
        }
        Ok(())
    }
    fn commit(&self) -> fips_file_transfer::Result<Vec<String>> {
        let mut state = self.state.lock().map_err(|_| "File export unavailable")?;
        let export = state.as_mut().ok_or("File export not prepared")?;
        if !export.committed {
            for file in &export.files {
                unix_storage::set_owner(&self.config, file, false).map_err(|e| e.to_string())?;
            }
            export.directory.sync_all().map_err(|e| e.to_string())?;
            unix_storage::set_owner(&self.config, &export.directory, true)
                .map_err(|e| e.to_string())?;
            export.committed = true;
        }
        Ok(export.paths.clone())
    }
    fn abort(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.take();
        }
    }
}
