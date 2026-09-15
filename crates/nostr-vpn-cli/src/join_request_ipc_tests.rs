use super::*;

use std::collections::HashSet;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::time::Instant;

fn test_dir() -> PathBuf {
    let nonce = rand::random::<u64>();
    let dir = Path::new("/tmp").join(format!("nvpn-join-ipc-{nonce}"));
    fs::create_dir(&dir).expect("create temp dir");
    dir
}

fn config_in(dir: &Path) -> PathBuf {
    let config = dir.join("config.toml");
    fs::write(&config, b"").expect("create config");
    config
}

#[tokio::test]
async fn join_request_preserves_a_running_daemons_rejection() {
    let dir = test_dir();
    let config = config_in(&dir);
    let (request_tx, mut request_rx) = tokio::sync::mpsc::unbounded_channel();
    let server = JoinRequestIpcServer::spawn(&config, request_tx).unwrap();
    let client = crate::pairing_qr::run_join_request(crate::JoinRequestArgs {
        config: Some(config),
        no_wait: true,
        no_qr: true,
        reset: false,
    });
    let daemon = async {
        request_rx
            .recv()
            .await
            .unwrap()
            .response
            .send(Err(
                "this device is already approved for its active network".into(),
            ))
            .unwrap();
    };
    let (result, ()) = tokio::join!(client, daemon);
    assert_eq!(
        result.unwrap_err().to_string(),
        "this device is already approved for its active network"
    );
    drop(server);
    fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn current_reset_permissions_and_cleanup_use_one_socket() {
    let dir = test_dir();
    let config = config_in(&dir);
    let (request_tx, mut request_rx) = tokio::sync::mpsc::unbounded_channel();
    let server = JoinRequestIpcServer::spawn(&config, request_tx).expect("bind IPC");

    for (reset, expected) in [
        (false, "nvpn://join-request/current"),
        (true, "nvpn://join-request/reset"),
    ] {
        let client = request_daemon_join_request_link(&config, reset);
        let daemon = async {
            let request = request_rx.recv().await.expect("accept request");
            assert_eq!(request.reset, reset);
            request.response.send(Ok(expected.into())).expect("respond");
        };
        let (actual, ()) = tokio::join!(client, daemon);
        assert_eq!(actual.expect("request link"), expected);
    }

    let socket = daemon_join_request_socket_path(&config).expect("socket path");
    let socket_metadata = fs::symlink_metadata(&socket).unwrap();
    assert_eq!(
        (socket_metadata.uid(), socket_metadata.gid()),
        server.runtime_dir.owner
    );
    assert_ne!(socket_metadata.permissions().mode() & 0o200, 0);
    assert_eq!(
        fs::symlink_metadata(socket.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    drop(server);
    assert!(!socket.exists());
    fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn stalled_clients_and_daemon_response_do_not_block_the_next_request() {
    let dir = test_dir();
    let config = config_in(&dir);
    let (request_tx, mut request_rx) = tokio::sync::mpsc::unbounded_channel();
    let server = JoinRequestIpcServer::spawn(&config, request_tx).unwrap();
    let stalled_stream = UnixStream::connect(daemon_join_request_socket_path(&config).unwrap())
        .await
        .unwrap();
    let config_for_stalled_request = config.clone();
    let stalled_request = tokio::spawn(async move {
        request_daemon_join_request_link(&config_for_stalled_request, false).await
    });
    let stalled_response = request_rx.recv().await.unwrap().response;

    let started = Instant::now();
    let client = request_daemon_join_request_link(&config, true);
    let daemon = async {
        let request = request_rx.recv().await.unwrap();
        assert!(request.reset);
        request
            .response
            .send(Ok("nvpn://join-request/next".into()))
            .unwrap();
    };
    let (actual, ()) = tokio::join!(client, daemon);
    assert_eq!(actual.unwrap(), "nvpn://join-request/next");
    assert!(started.elapsed() < Duration::from_secs(1));

    drop(stalled_response);
    drop(stalled_stream);
    stalled_request.abort();
    drop(server);
    fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn excess_stalled_clients_are_rejected_without_blocking_later_work() {
    let dir = test_dir();
    let config = config_in(&dir);
    let socket = daemon_join_request_socket_path(&config).unwrap();
    let (request_tx, mut request_rx) = tokio::sync::mpsc::unbounded_channel();
    let server = JoinRequestIpcServer::spawn(&config, request_tx).unwrap();
    let mut stalled = Vec::new();
    for _ in 0..JOIN_REQUEST_IPC_MAX_CLIENTS {
        stalled.push(UnixStream::connect(&socket).await.unwrap());
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut excess = UnixStream::connect(&socket).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), excess.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );

    drop(stalled.pop());
    tokio::time::sleep(Duration::from_millis(20)).await;
    let client = request_daemon_join_request_link(&config, false);
    let daemon = async {
        request_rx
            .recv()
            .await
            .unwrap()
            .response
            .send(Ok("nvpn://join-request/after-cap".into()))
            .unwrap();
    };
    let (actual, ()) = tokio::join!(client, daemon);
    assert_eq!(actual.unwrap(), "nvpn://join-request/after-cap");

    drop(stalled);
    drop(server);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn relative_config_path_has_the_same_absolute_identity() {
    let relative = Path::new("Cargo.toml");
    let absolute = std::env::current_dir().unwrap().join(relative);
    let relative_identity = absolute_config_identity(relative).unwrap();
    assert!(relative_identity.is_absolute());
    assert_eq!(
        relative_identity,
        absolute_config_identity(&absolute).unwrap()
    );
}

#[test]
fn runtime_symlink_is_rejected_without_touching_its_target() {
    let dir = test_dir();
    let config = config_in(&dir);
    let target = dir.join("target");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
    symlink(&target, dir.join(JOIN_REQUEST_RUNTIME_DIR)).unwrap();

    let error = PrivateRuntimeDir::prepare(&config)
        .err()
        .expect("reject symlink");
    assert!(error.to_string().contains("securely open"));
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o755
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn runtime_swap_is_detected_and_cleanup_stays_fd_anchored() {
    let dir = test_dir();
    let config = config_in(&dir);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (request_tx, _request_rx) = tokio::sync::mpsc::unbounded_channel();
    let server =
        runtime.block_on(async { JoinRequestIpcServer::spawn(&config, request_tx).unwrap() });
    let socket = daemon_join_request_socket_path(&config).unwrap();
    let displaced = dir.join("displaced");
    fs::rename(socket.parent().unwrap(), &displaced).unwrap();
    fs::create_dir(socket.parent().unwrap()).unwrap();
    fs::write(&socket, b"replacement").unwrap();

    assert!(server.runtime_dir.verify_path_identity().is_err());
    drop(server);
    assert_eq!(fs::read(&socket).unwrap(), b"replacement");
    assert!(!displaced.join(socket.file_name().unwrap()).exists());
    fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn bind_never_follows_a_swapped_runtime_path() {
    let dir = test_dir();
    let config = config_in(&dir);
    let runtime = PrivateRuntimeDir::prepare(&config).unwrap();
    let name = socket_name(&config);
    let displaced = dir.join("displaced");
    let target = dir.join("target");
    fs::rename(&runtime.path, &displaced).unwrap();
    fs::create_dir(&target).unwrap();
    symlink(&target, &runtime.path).unwrap();

    let error = bind_private_socket(&runtime, &name).expect_err("reject swapped path");
    assert!(error.to_string().contains("runtime directory was replaced"));
    assert!(fs::read_dir(&target).unwrap().next().is_none());

    drop(runtime);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn bind_staging_is_random_and_on_the_runtime_filesystem() {
    let dir = test_dir();
    let config = config_in(&dir);
    let runtime = PrivateRuntimeDir::prepare(&config).unwrap();
    let mut names = HashSet::new();
    for _ in 0..64 {
        let staging = PrivateBindDir::create(&runtime).unwrap();
        assert_eq!(
            staging.dir.metadata().unwrap().dev(),
            runtime.dir.metadata().unwrap().dev()
        );
        assert_eq!(staging.path.parent(), Some(runtime.path.as_path()));
        assert!(names.insert(staging.name.to_bytes().to_vec()));
    }
    assert_eq!(names.len(), 64);

    drop(runtime);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn socket_path_reports_the_unix_length_limit() {
    let dir = test_dir();
    let config = dir.join("x".repeat(120)).join("config.toml");
    fs::create_dir(config.parent().unwrap()).unwrap();
    let error = daemon_join_request_socket_path(&config).expect_err("long path");
    assert!(error.to_string().contains("socket path is too long"));
    assert!(
        error
            .to_string()
            .contains("shorten the config directory path")
    );
    fs::remove_dir_all(dir).unwrap();
}
