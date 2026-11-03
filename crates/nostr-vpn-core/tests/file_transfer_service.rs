//! Exercise the share-extension command boundary with only the background service.
//! No app runtime or platform keychain participates in delivery.
#![cfg(unix)]
use std::{fs, net::UdpSocket, path::PathBuf, sync::Arc, time::Duration};

use nostr_sdk::prelude::{Keys, ToBech32};
use nostr_vpn_core::{
    config::AppConfig,
    file_transfers::{
        FileCommand, FileTransferService, TransferState, enqueue, read_state, stage_source,
        state_dir,
    },
};

struct Peer {
    directory: PathBuf,
    config: PathBuf,
    app: AppConfig,
    endpoint: Arc<fips_core::FipsEndpoint>,
}

impl Peer {
    async fn new(address: std::net::SocketAddrV4) -> Self {
        let keys = Keys::generate();
        let mut network = fips_core::Config::new();
        network.node.control.enabled = false;
        network.node.discovery.local.rendezvous_addr = address;
        network.node.discovery.local.retry_interval_ms = 20;
        network.node.discovery.lan.enabled = false;
        network.node.discovery.nostr.enabled = false;
        network.node.routing.mode = fips_core::config::RoutingMode::ReplyLearned;
        let secret = keys.secret_key().to_bech32().unwrap();
        let endpoint = Arc::new(
            Box::pin(
                fips_core::FipsEndpoint::builder()
                    .config(network)
                    .identity_nsec(secret.clone())
                    .local_rendezvous()
                    .without_system_tun()
                    .bind(),
            )
            .await
            .unwrap(),
        );
        let directory =
            std::env::temp_dir().join(format!("nvpn-file-service-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        private(&directory, true);
        let config = directory.join("config.toml");
        let mut app = AppConfig::default();
        app.nostr.secret_key = secret;
        app.nostr.public_key = keys.public_key().to_hex();
        Self {
            directory,
            config,
            app,
            endpoint,
        }
    }

    fn authorize(&mut self, other: &Self) {
        let own = self.app.nostr.public_key.clone();
        let network = &mut self.app.networks[0];
        network.enabled = true;
        network.local_identity_confirmation_pending = false;
        network.devices = vec![own.clone(), other.app.nostr.public_key.clone()];
        network.admins = vec![own];
        fs::write(&self.config, self.app.plaintext_toml().unwrap()).unwrap();
        private(&self.config, false);
    }

    async fn state(&self, id: &str, status: &str) -> TransferState {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(row) = read_state(&self.config)
                    .unwrap()
                    .into_iter()
                    .find(|row| row.id == id)
                {
                    assert_ne!(row.status, "failed", "transfer failed: {:?}", row.error);
                    if row.status == status {
                        return row;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("background service did not reach {status}"))
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn private(path: &std::path::Path, directory: bool) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn share_command_sends_without_app_after_service_starts_and_recipient_accepts() {
    let address = match UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
    {
        std::net::SocketAddr::V4(address) => address,
        _ => unreachable!(),
    };
    let mut sender = Peer::new(address).await;
    let mut receiver = Peer::new(address).await;
    sender.authorize(&receiver);
    receiver.authorize(&sender);
    let source = sender.directory.join("photo.bin");
    let contents = vec![0xab; 180_123];
    fs::write(&source, &contents).unwrap();
    let staged = stage_source(&sender.config, &source).unwrap();
    // This is the exact envelope written by iOS FileTransferStorage.enqueue.
    let id = uuid::Uuid::new_v4().simple().to_string();
    let commands = state_dir(&sender.config).join("commands");
    fs::create_dir_all(&commands).unwrap();
    private(&state_dir(&sender.config), true);
    private(&commands, true);
    let command = commands.join(format!("{id}.json"));
    fs::write(&command, serde_json::to_vec(&serde_json::json!({
        "id": id, "command": { "type": "send", "npub": receiver.endpoint.npub(), "paths": [staged] }
    })).unwrap()).unwrap();
    private(&command, false);
    assert_eq!(read_state(&sender.config).unwrap()[0].status, "queued");

    let sender_service = FileTransferService::start(sender.endpoint.clone(), sender.config.clone());
    let receiver_service =
        FileTransferService::start(receiver.endpoint.clone(), receiver.config.clone());
    let offered = receiver.state(&id, "offered").await;
    assert_eq!(
        offered.transferred_bytes, 0,
        "sent file bytes before receiver approval"
    );
    enqueue(&receiver.config, FileCommand::Accept { id: id.clone() }).unwrap();
    let received = receiver.state(&id, "completed").await;
    sender.state(&id, "completed").await;
    assert_eq!(
        fs::read(received.files[0].local_path.as_ref().unwrap()).unwrap(),
        contents
    );
    assert!(
        !command.exists(),
        "service did not acknowledge the durable share command"
    );
    drop(sender_service);
    drop(receiver_service);
    sender.endpoint.shutdown().await.unwrap();
    receiver.endpoint.shutdown().await.unwrap();
}
