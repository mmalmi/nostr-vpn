use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

const JOIN_REQUEST_IPC_TIMEOUT: Duration = Duration::from_secs(2);
const JOIN_REQUEST_IPC_RESPONSE_LIMIT: u64 = 64 * 1024;
const JOIN_REQUEST_IPC_MAX_CLIENTS: usize = 16;
const JOIN_REQUEST_RUNTIME_DIR: &str = ".nvpn-runtime";
const JOIN_REQUEST_RUNTIME_NAME: &CStr = c".nvpn-runtime";
const PRIVATE_BIND_SOCKET: &CStr = c"s";
const DIR_OPEN_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

pub(crate) struct JoinRequestIpcServer {
    task: tokio::task::JoinHandle<()>,
    runtime_dir: PrivateRuntimeDir,
    socket_name: CString,
}

impl JoinRequestIpcServer {
    pub(crate) fn spawn(
        config_path: &Path,
        requests: tokio::sync::mpsc::UnboundedSender<crate::DaemonJoinRequestIpcRequest>,
    ) -> Result<Self> {
        let config_path = absolute_config_identity(config_path)?;
        let mut runtime_dir = PrivateRuntimeDir::prepare(&config_path)?;
        let socket_name = socket_name(&config_path);
        socket_path(&runtime_dir.path, &socket_name)?;
        let listener = bind_private_socket(&runtime_dir, &socket_name)?;
        if let Err(error) = runtime_dir.publish() {
            let _ = unlinkat(&runtime_dir.dir, &socket_name);
            return Err(error);
        }
        let task = tokio::spawn(serve_join_request_socket(listener, requests));
        Ok(Self {
            task,
            runtime_dir,
            socket_name,
        })
    }
}

impl Drop for JoinRequestIpcServer {
    fn drop(&mut self) {
        self.task.abort();
        let _ = unlinkat(&self.runtime_dir.dir, &self.socket_name);
    }
}

async fn serve_join_request_socket(
    listener: UnixListener,
    requests: tokio::sync::mpsc::UnboundedSender<crate::DaemonJoinRequestIpcRequest>,
) {
    let permits = Arc::new(tokio::sync::Semaphore::new(JOIN_REQUEST_IPC_MAX_CLIENTS));
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error) => {
                eprintln!("daemon: failed to accept join-request IPC connection: {error}");
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let requests = requests.clone();
        tokio::spawn(async move {
            let _permit = permit;
            handle_join_request(stream, requests).await;
        });
    }
}

async fn handle_join_request(
    mut stream: UnixStream,
    requests: tokio::sync::mpsc::UnboundedSender<crate::DaemonJoinRequestIpcRequest>,
) {
    let response = tokio::time::timeout(JOIN_REQUEST_IPC_TIMEOUT, async {
        let mut command = [0_u8];
        stream.read_exact(&mut command).await?;
        ensure!(command[0] <= 1, "invalid join-request IPC command");
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        requests
            .send(crate::DaemonJoinRequestIpcRequest {
                reset: command[0] == 1,
                response: response_tx,
            })
            .map_err(|_| anyhow!("daemon is shutting down"))?;
        response_rx
            .await
            .map_err(|_| anyhow!("daemon did not answer join-request IPC"))?
            .map_err(anyhow::Error::msg)
    })
    .await
    .context("timed out handling the daemon join-request IPC")
    .and_then(|response| response);
    respond_with_join_request(stream, response).await;
}

async fn respond_with_join_request(mut stream: UnixStream, response: Result<String>) {
    let response = response.unwrap_or_else(|error| format!("error: {error}"));
    let write = tokio::time::timeout(JOIN_REQUEST_IPC_TIMEOUT, async {
        stream.write_all(response.as_bytes()).await?;
        stream.shutdown().await
    })
    .await;
    if let Err(error) = write {
        eprintln!("daemon: join-request IPC response timed out: {error}");
    } else if let Ok(Err(error)) = write {
        eprintln!("daemon: failed to write join-request IPC response: {error}");
    }
}

pub(crate) async fn request_daemon_join_request_link(
    config_path: &Path,
    reset: bool,
) -> Result<String> {
    let path = daemon_join_request_socket_path(config_path)?;
    let mut stream = tokio::time::timeout(JOIN_REQUEST_IPC_TIMEOUT, UnixStream::connect(&path))
        .await
        .context("timed out connecting to the nVPN daemon join-request socket")?
        .with_context(|| format!(
            "the nVPN daemon must be running to create an ephemeral join request (failed to connect to {})",
            path.display()
        ))?;
    tokio::time::timeout(
        JOIN_REQUEST_IPC_TIMEOUT,
        stream.write_all(&[u8::from(reset)]),
    )
    .await
    .context("timed out writing the nVPN daemon join-request command")??;
    let mut response = String::new();
    tokio::time::timeout(
        JOIN_REQUEST_IPC_TIMEOUT,
        stream
            .take(JOIN_REQUEST_IPC_RESPONSE_LIMIT)
            .read_to_string(&mut response),
    )
    .await
    .context("timed out reading the nVPN daemon join request")??;
    let response = response.trim();
    if let Some(error) = response.strip_prefix("error: ") {
        return Err(anyhow!(error.to_string()));
    }
    ensure!(
        response.starts_with("nvpn://join-request/"),
        "daemon returned an invalid join-request link"
    );
    Ok(response.to_string())
}

fn daemon_join_request_socket_path(config_path: &Path) -> Result<PathBuf> {
    let config_path = absolute_config_identity(config_path)?;
    socket_path(
        &config_parent(&config_path)?.join(JOIN_REQUEST_RUNTIME_DIR),
        &socket_name(&config_path),
    )
}

fn absolute_config_identity(config_path: &Path) -> Result<PathBuf> {
    let absolute = if config_path.is_absolute() {
        config_path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to resolve the current directory for the nVPN config path")?
            .join(config_path)
    };
    if let Ok(canonical) = fs::canonicalize(&absolute) {
        return Ok(canonical);
    }
    let name = absolute
        .file_name()
        .ok_or_else(|| anyhow!("nVPN config path must name a file"))?;
    let parent = config_parent(&absolute)?;
    Ok(fs::canonicalize(parent)
        .with_context(|| format!("failed to resolve config directory {}", parent.display()))?
        .join(name))
}

fn socket_name(config_path: &Path) -> CString {
    let scope = hex::encode(Sha256::digest(config_path.as_os_str().as_bytes()));
    CString::new(format!("join-{}.sock", &scope[..16])).expect("socket name has no NUL")
}

fn socket_path(runtime_dir: &Path, socket_name: &CStr) -> Result<PathBuf> {
    let path = runtime_dir.join(std::ffi::OsStr::from_bytes(socket_name.to_bytes()));
    let capacity = unsafe { std::mem::zeroed::<libc::sockaddr_un>() }
        .sun_path
        .len();
    let length = path.as_os_str().as_bytes().len();
    ensure!(
        length < capacity,
        "nVPN join-request socket path is too long ({length} bytes; maximum {}): {}; shorten the config directory path",
        capacity - 1,
        path.display()
    );
    Ok(path)
}

fn config_parent(config_path: &Path) -> Result<&Path> {
    config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("nVPN config path must have a parent directory"))
}

struct PrivateRuntimeDir {
    parent: File,
    dir: File,
    path: PathBuf,
    owner: (u32, u32),
    published: bool,
}

impl PrivateRuntimeDir {
    fn prepare(config_path: &Path) -> Result<Self> {
        let parent_path = config_parent(config_path)?;
        let parent = open_dir(parent_path).context("failed to open nVPN config directory")?;
        match mkdirat(&parent, JOIN_REQUEST_RUNTIME_NAME, 0o700) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).context("failed to create join-request runtime directory");
            }
        }
        let dir = openat(&parent, JOIN_REQUEST_RUNTIME_NAME, DIR_OPEN_FLAGS)
            .context("failed to securely open join-request runtime directory")?;
        let owner = config_owner(config_path, &parent)?;
        let daemon_owner = (unsafe { libc::geteuid() }, unsafe { libc::getegid() });
        set_fd_owner_mode(&dir, daemon_owner.0, daemon_owner.1, 0o700)
            .context("failed to lock the join-request runtime directory")?;
        Ok(Self {
            parent,
            dir,
            path: parent_path.join(JOIN_REQUEST_RUNTIME_DIR),
            owner,
            published: false,
        })
    }

    fn publish(&mut self) -> Result<()> {
        set_fd_owner_mode(&self.dir, self.owner.0, self.owner.1, 0o700)
            .context("failed to publish the join-request runtime directory")?;
        self.verify_path_identity()?;
        self.published = true;
        Ok(())
    }

    fn verify_path_identity(&self) -> Result<()> {
        let current = openat(&self.parent, JOIN_REQUEST_RUNTIME_NAME, DIR_OPEN_FLAGS)
            .context("join-request runtime directory was replaced")?;
        ensure_same_file(&self.dir, &current)
    }
}

impl Drop for PrivateRuntimeDir {
    fn drop(&mut self) {
        if !self.published {
            let _ = set_fd_owner_mode(&self.dir, self.owner.0, self.owner.1, 0o700);
        }
    }
}

fn bind_private_socket(
    runtime_dir: &PrivateRuntimeDir,
    socket_name: &CStr,
) -> Result<UnixListener> {
    let temporary = PrivateBindDir::create(runtime_dir)?;
    let temporary_path = temporary.path.join("s");
    let listener = UnixListener::bind(&temporary_path)
        .with_context(|| format!("failed to bind {}", temporary_path.display()))?;
    protect_socket_entry(
        &temporary.dir,
        PRIVATE_BIND_SOCKET,
        runtime_dir.owner.0,
        runtime_dir.owner.1,
    )?;
    remove_stale_socket(&runtime_dir.dir, socket_name)?;
    runtime_dir.verify_path_identity()?;
    zero(unsafe {
        libc::renameat(
            temporary.dir.as_raw_fd(),
            PRIVATE_BIND_SOCKET.as_ptr(),
            runtime_dir.dir.as_raw_fd(),
            socket_name.as_ptr(),
        )
    })
    .context("failed to publish join-request IPC socket")?;
    if let Err(error) = verify_socket_entry(
        &runtime_dir.dir,
        socket_name,
        runtime_dir.owner.0,
        runtime_dir.owner.1,
    )
    .and_then(|()| runtime_dir.verify_path_identity())
    {
        let _ = unlinkat(&runtime_dir.dir, socket_name);
        return Err(error);
    }
    Ok(listener)
}

struct PrivateBindDir<'a> {
    parent: &'a File,
    dir: File,
    name: CString,
    path: PathBuf,
}

impl<'a> PrivateBindDir<'a> {
    fn create(runtime: &'a PrivateRuntimeDir) -> Result<Self> {
        runtime.verify_path_identity()?;
        for _ in 0..8 {
            let name = CString::new(hex::encode(rand::random::<[u8; 12]>())).unwrap();
            match mkdirat(&runtime.dir, &name, 0o700) {
                Ok(()) => {
                    let dir = openat(&runtime.dir, &name, DIR_OPEN_FLAGS)?;
                    ensure!(
                        runtime.dir.metadata()?.dev() == dir.metadata()?.dev(),
                        "join-request staging crossed a filesystem boundary"
                    );
                    let path = runtime
                        .path
                        .join(std::ffi::OsStr::from_bytes(name.to_bytes()));
                    return Ok(Self {
                        parent: &runtime.dir,
                        dir,
                        name,
                        path,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error).context("failed to create private bind directory"),
            }
        }
        Err(anyhow!(
            "failed to reserve a private join-request bind directory"
        ))
    }
}

impl Drop for PrivateBindDir<'_> {
    fn drop(&mut self) {
        let _ = unlinkat(&self.dir, PRIVATE_BIND_SOCKET);
        let _ = rmdirat(self.parent, &self.name);
    }
}

fn config_owner(config_path: &Path, parent: &File) -> Result<(u32, u32)> {
    let name = c_string(
        config_path
            .file_name()
            .ok_or_else(|| anyhow!("nVPN config path must name a file"))?
            .as_bytes(),
    )?;
    let metadata = openat(
        parent,
        &name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
    .and_then(|file| file.metadata())
    .or_else(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            parent.metadata()
        } else {
            Err(error)
        }
    });
    let metadata = metadata
        .with_context(|| format!("failed to determine owner for {}", config_path.display()))?;
    let gid = if unsafe { libc::geteuid() } == 0 {
        metadata.gid()
    } else {
        unsafe { libc::getegid() }
    };
    Ok((metadata.uid(), gid))
}

fn set_fd_owner_mode(file: &File, uid: u32, gid: u32, mode: u32) -> Result<()> {
    zero(unsafe { libc::fchown(file.as_raw_fd(), uid, gid) }).context("fchown failed")?;
    zero(unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) })
        .context("fchmod failed")?;
    Ok(())
}

fn protect_socket_entry(dir: &File, name: &CStr, uid: u32, gid: u32) -> Result<()> {
    let metadata = metadata_at(dir, name)?;
    ensure!(
        is_socket(&metadata),
        "join-request IPC entry is not a socket"
    );
    // The verified 0700 parent gates access; mounted filesystems may reject socket setattr.
    if metadata.st_uid != uid || metadata.st_gid != gid {
        zero(unsafe { libc::fchownat(dir.as_raw_fd(), name.as_ptr(), uid, gid, 0) })
            .context("fchownat socket failed")?;
    }
    verify_socket_entry(dir, name, uid, gid)
}
fn verify_socket_entry(dir: &File, name: &CStr, uid: u32, gid: u32) -> Result<()> {
    let metadata = metadata_at(dir, name)?;
    ensure!(
        is_socket(&metadata)
            && metadata.st_uid == uid
            && metadata.st_gid == gid
            && metadata.st_mode & 0o200 != 0,
        "join-request IPC socket type, owner, or owner access changed"
    );
    Ok(())
}
fn remove_stale_socket(dir: &File, name: &CStr) -> Result<()> {
    match metadata_at(dir, name) {
        Ok(metadata) if is_socket(&metadata) => {
            unlinkat(dir, name).context("failed to remove stale join-request IPC socket")
        }
        Ok(_) => Err(anyhow!(
            "refusing to replace non-socket join-request IPC entry"
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("failed to inspect join-request IPC entry"),
    }
}

fn open_dir(path: &Path) -> io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    file_from_fd(unsafe { libc::open(path.as_ptr(), DIR_OPEN_FLAGS) })
}

fn openat(parent: &File, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    file_from_fd(fd)
}

fn file_from_fd(fd: libc::c_int) -> io::Result<File> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn mkdirat(parent: &File, name: &CStr, mode: u32) -> io::Result<()> {
    zero(unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) })
}

fn unlinkat(parent: &File, name: &CStr) -> io::Result<()> {
    zero(unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) })
}
fn rmdirat(parent: &File, name: &CStr) -> io::Result<()> {
    zero(unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) })
}

fn metadata_at(parent: &File, name: &CStr) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    zero(unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    Ok(unsafe { stat.assume_init() })
}

fn is_socket(metadata: &libc::stat) -> bool {
    metadata.st_mode & libc::S_IFMT as libc::mode_t == libc::S_IFSOCK as libc::mode_t
}

fn ensure_same_file(left: &File, right: &File) -> Result<()> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    ensure!(
        left.dev() == right.dev() && left.ino() == right.ino(),
        "join-request runtime directory was replaced"
    );
    Ok(())
}

fn c_string(bytes: &[u8]) -> Result<CString> {
    CString::new(bytes).map_err(|_| anyhow!("join-request IPC path contains NUL"))
}
fn zero(result: libc::c_int) -> io::Result<()> {
    (result == 0)
        .then_some(())
        .ok_or_else(io::Error::last_os_error)
}

#[cfg(test)]
#[path = "join_request_ipc_tests.rs"]
mod tests;
