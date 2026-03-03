use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use eframe::egui;
use nostr_vpn_core::config::{AppConfig, normalize_nostr_pubkey};
use nostr_vpn_core::control::{PeerAnnouncement, PeerDirectory};
use nostr_vpn_core::signaling::{NostrSignalingClient, SignalPayload};
use tokio::runtime::Runtime;

struct NostrVpnGui {
    runtime: Runtime,
    config_path: PathBuf,
    config: AppConfig,
    status: String,
    connected: bool,
    peers: PeerDirectory,
    client: Option<Arc<NostrSignalingClient>>,
    signal_rx: Option<mpsc::Receiver<nostr_vpn_core::signaling::SignalEnvelope>>,
    show_settings: bool,
    relay_input: String,
    participant_input: String,
}

impl NostrVpnGui {
    fn new() -> Result<Self> {
        let runtime = Runtime::new().context("failed to create tokio runtime")?;
        let config_path = default_config_path();

        let mut config = if config_path.exists() {
            AppConfig::load(&config_path).context("failed to load config")?
        } else {
            let generated = AppConfig::generated();
            let _ = generated.save(&config_path);
            generated
        };
        config.ensure_defaults();

        let relay_input = config.nostr.relays.join("\n");
        let participant_input = config.participants.join("\n");

        Ok(Self {
            runtime,
            config_path,
            config,
            status: "Disconnected".to_string(),
            connected: false,
            peers: PeerDirectory::default(),
            client: None,
            signal_rx: None,
            show_settings: false,
            relay_input,
            participant_input,
        })
    }

    fn connect(&mut self) {
        if self.connected {
            self.status = "Already connected".to_string();
            return;
        }

        match self.connect_inner() {
            Ok(()) => {
                self.connected = true;
                self.status = format!("Connected to {} relays", self.config.nostr.relays.len());
            }
            Err(error) => {
                self.status = format!("Connect failed: {error}");
            }
        }
    }

    fn connect_inner(&mut self) -> Result<()> {
        let relays = self.config.nostr.relays.clone();
        let network_id = self.config.effective_network_id();
        let client = Arc::new(NostrSignalingClient::from_secret_key(
            network_id,
            &self.config.nostr.secret_key,
            self.config.participant_pubkeys_hex(),
        )?);
        self.runtime.block_on(client.connect(&relays))?;

        let (tx, rx) = mpsc::channel();
        let recv_client = client.clone();
        self.runtime.spawn(async move {
            loop {
                let Some(message) = recv_client.recv().await else {
                    break;
                };

                if tx.send(message).is_err() {
                    break;
                }
            }
        });

        self.client = Some(client);
        self.signal_rx = Some(rx);

        Ok(())
    }

    fn disconnect(&mut self) {
        if !self.connected {
            return;
        }

        if let Some(client) = self.client.take() {
            self.runtime.block_on(client.disconnect());
        }

        self.signal_rx = None;
        self.connected = false;
        self.status = "Disconnected".to_string();
    }

    fn announce_now(&mut self) {
        let Some(client) = self.client.clone() else {
            self.status = "Connect first, then announce".to_string();
            return;
        };

        let announcement = PeerAnnouncement {
            node_id: self.config.node.id.clone(),
            public_key: self.config.node.public_key.clone(),
            endpoint: self.config.node.endpoint.clone(),
            tunnel_ip: self.config.node.tunnel_ip.clone(),
            timestamp: unix_timestamp(),
        };

        match self
            .runtime
            .block_on(client.publish(SignalPayload::Announce(announcement)))
        {
            Ok(()) => {
                self.status = "Announcement sent".to_string();
            }
            Err(error) => {
                self.status = format!("Announcement failed: {error}");
            }
        }
    }

    fn handle_signals(&mut self) {
        let mut pending = Vec::new();
        if let Some(rx) = &self.signal_rx {
            while let Ok(message) = rx.try_recv() {
                pending.push(message);
            }
        }

        for message in pending {
            if let SignalPayload::Announce(announcement) = message.payload {
                self.peers.apply(announcement);
            }
        }
    }

    fn save_settings(&mut self) {
        let relays: Vec<String> = self
            .relay_input
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToString::to_string)
            .collect();

        if relays.is_empty() {
            self.status = "At least one relay is required".to_string();
            return;
        }

        let mut participants = Vec::new();
        for participant in self
            .participant_input
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            match normalize_nostr_pubkey(participant) {
                Ok(pubkey) => participants.push(pubkey),
                Err(error) => {
                    self.status = format!("Invalid participant '{participant}': {error}");
                    return;
                }
            }
        }

        participants.sort();
        participants.dedup();

        self.config.nostr.relays = relays;
        self.config.participants = participants;
        self.config.ensure_defaults();

        if let Err(error) = self.config.save(&self.config_path) {
            self.status = format!("Failed to save settings: {error}");
            return;
        }

        self.status = format!("Saved {}", self.config_path.display());
    }
}

impl eframe::App for NostrVpnGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_signals();

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.menu_button("Menu", |ui| {
                    if ui.button("Connect").clicked() {
                        self.connect();
                        ui.close();
                    }
                    if ui.button("Disconnect").clicked() {
                        self.disconnect();
                        ui.close();
                    }
                    if ui.button("Announce").clicked() {
                        self.announce_now();
                        ui.close();
                    }
                    if ui.button("Settings").clicked() {
                        self.show_settings = true;
                        ui.close();
                    }
                    if ui.button("Quit").clicked() {
                        self.disconnect();
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        ui.close();
                    }
                });

                if ui.button("Connect").clicked() {
                    self.connect();
                }
                if ui.button("Disconnect").clicked() {
                    self.disconnect();
                }
                if ui.button("Announce").clicked() {
                    self.announce_now();
                }
                if ui.button("Settings").clicked() {
                    self.show_settings = !self.show_settings;
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Nostr VPN");
            ui.label(format!("Network: {}", self.config.effective_network_id()));
            ui.label(format!("Node ID: {}", self.config.node.id));
            ui.label(format!("Nostr Pubkey: {}", self.config.nostr.public_key));
            ui.label(format!("Status: {}", self.status));
            ui.separator();

            ui.label("Discovered Peers");
            let peers = self.peers.all();
            if peers.is_empty() {
                ui.label("No peers discovered yet.");
            } else {
                egui::Grid::new("peer-grid").striped(true).show(ui, |ui| {
                    ui.strong("Node");
                    ui.strong("Endpoint");
                    ui.strong("Tunnel IP");
                    ui.end_row();

                    for peer in peers {
                        ui.label(peer.node_id);
                        ui.label(peer.endpoint);
                        ui.label(peer.tunnel_ip);
                        ui.end_row();
                    }
                });
            }
        });

        if self.show_settings {
            let mut open = self.show_settings;
            let mut save_clicked = false;
            let mut close_clicked = false;

            egui::Window::new("Settings")
                .open(&mut open)
                .resizable(true)
                .show(ctx, |ui| {
                    ui.label(format!("Config: {}", self.config_path.display()));
                    ui.horizontal(|ui| {
                        ui.label("Fallback Network ID");
                        ui.text_edit_singleline(&mut self.config.network_id);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Node Name");
                        ui.text_edit_singleline(&mut self.config.node_name);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Endpoint");
                        ui.text_edit_singleline(&mut self.config.node.endpoint);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Tunnel IP");
                        ui.text_edit_singleline(&mut self.config.node.tunnel_ip);
                    });
                    ui.label("Participants (npub/hex, one per line)");
                    ui.text_edit_multiline(&mut self.participant_input);
                    ui.label("Relays (one per line)");
                    ui.text_edit_multiline(&mut self.relay_input);

                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            save_clicked = true;
                        }
                        if ui.button("Close").clicked() {
                            close_clicked = true;
                        }
                    });
                });

            if save_clicked {
                self.save_settings();
            }
            if close_clicked {
                open = false;
            }
            self.show_settings = open;
        }

        ctx.request_repaint_after(Duration::from_millis(200));
    }
}

fn default_config_path() -> PathBuf {
    if let Some(mut path) = dirs::config_dir() {
        path.push("nvpn");
        path.push("config.toml");
        return path;
    }

    PathBuf::from("nvpn.toml")
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn main() -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Nostr VPN")
            .with_inner_size([460.0, 560.0]),
        ..Default::default()
    };

    let app = NostrVpnGui::new()?;

    eframe::run_native(
        "Nostr VPN",
        options,
        Box::new(move |_creation_context| Ok(Box::new(app))),
    )
    .map_err(|error| anyhow!("failed to run GUI: {error}"))
}
