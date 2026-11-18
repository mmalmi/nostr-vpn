//! Private, opt-in VPN exit credit on the same authenticated FIPS link as
//! other services. The account and its reservation limits belong to the node.
use super::{
    FipsPrivateMeshRuntime, FipsPrivateTunnelConfig, derive_mesh_tunnel_ip, normalize_nostr_pubkey,
    unix_timestamp,
};
use anyhow::{Context, Result, anyhow, ensure};
use fips_credit_link::{CreditLink, InvoiceQuote, LinkPolicy, ServiceHandler, ServiceRequest};
use peer_payments::{
    Account, AccountStore, Agreement, Book, Buyer, ControlMessage, Controller, Keypair, Limits,
    PurchaseIntent, SpendingLimits,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
};

#[cfg(unix)]
use fips_credit_link::wallet::ConnectedWallet;
#[cfg(not(unix))]
struct ConnectedWallet {
    rpc_socket: PathBuf,
    network: String,
    node_id: String,
}

const SERVICE: &str = "vpn.exit.upload_bytes";
const PRICE_DENOMINATOR: u64 = nostr_vpn_core::paid_routes::PAID_ROUTE_PRICE_BYTES_PER_GB * 1000; // msat per decimal GB expressed in credit sats per byte
pub(crate) const JOURNAL: &str = "peer-credit.sqlite";
pub(crate) const POLICY: &str = "peer-credit-policy.json";

fn key_from_nsec(nsec: &str) -> Result<Keypair> {
    let keys = nostr_sdk::Keys::parse(nsec).map_err(|_| anyhow!("invalid VPN identity"))?;
    keys.secret_key()
        .to_secret_hex()
        .parse()
        .map_err(|_| anyhow!("invalid credit identity"))
}

pub(crate) fn initialize(
    dir: &Path,
    nsec: &str,
    peers: &[String],
    total: u64,
    per_peer: u64,
    trial: Option<peer_payments::TrialPolicy>,
) -> Result<()> {
    let owner = key_from_nsec(nsec)?.x_only_public_key().0.to_string();
    let accepted = peers
        .iter()
        .map(|p| normalize_nostr_pubkey(p))
        .collect::<Result<Vec<_>>>()?;
    let limits = Limits {
        max_total_exposure_sat: total,
        max_peer_exposure_sat: per_peer,
        ..Limits::default()
    };
    let mut book = Book::new(&owner, limits, accepted)?;
    if let Some(policy) = trial {
        book = book.with_trial_policy(policy)?;
    }
    let account = Account::new(book, Buyer::new(&owner, SpendingLimits::default())?)?;
    AccountStore::create(dir.join(JOURNAL), account)?;
    Ok(())
}

pub(crate) struct ExitPolicy {
    pub(super) upstream_peer: Option<String>,
    network: String,
    price_msat_per_gb: u64,
    max_sat: u64,
    max_lifetime: u64,
}
impl ExitPolicy {
    pub(super) fn from_config(config: &FipsPrivateTunnelConfig) -> Self {
        Self {
            upstream_peer: config
                .local_exit_seller_egress
                .as_ref()
                .and_then(|e| e.private_peer_pubkey())
                .map(str::to_owned),
            network: config.network_id.clone(),
            price_msat_per_gb: config.paid_exit.pricing.price_msat_per_gb,
            max_sat: config.paid_exit.channel.max_channel_capacity_sat,
            max_lifetime: config.paid_exit.channel.channel_expiry_secs.min(3600),
        }
    }
    fn verify(&self, peer: &str, terms: &Agreement) -> Result<IpAddr> {
        ensure!(
            self.upstream_peer.as_deref() != Some(peer),
            "upstream cannot buy its own exit"
        );
        ensure!(
            terms.payer == peer && terms.service == SERVICE,
            "wrong payer or service"
        );
        ensure!(
            terms.price_sat == self.price_msat_per_gb && terms.price_per_units == PRICE_DENOMINATOR,
            "price differs from the configured exit tariff"
        );
        ensure!(
            terms.max_amount_sat == terms.amount_for(terms.max_units)?
                && terms.max_amount_sat <= self.max_sat,
            "amount exceeds seller limits"
        );
        ensure!(
            terms
                .expires_at
                .checked_sub(terms.created_at)
                .is_some_and(|s| s > 0 && s <= self.max_lifetime),
            "invalid sale lifetime"
        );
        let ip = tunnel_address(&self.network, peer)?;
        ensure!(
            terms.resource == format!("internet-exit-upload:{ip}"),
            "wrong exit address"
        );
        Ok(ip)
    }
}
fn tunnel_address(network: &str, owner: &str) -> Result<IpAddr> {
    derive_mesh_tunnel_ip(network, owner)
        .and_then(|cidr| cidr.split_once('/').and_then(|(ip, _)| ip.parse().ok()))
        .context("no assigned tunnel address")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Command {
    ConnectWallet,
    AutoCashout {
        policy: Option<fips_credit_link::AutoCashout>,
    },
    Balance,
    OfferPayout {
        peer: String,
    },
    Quote {
        invoice: String,
    },
    Confirm {
        invoice: String,
        quote: InvoiceQuote,
        #[serde(default)]
        own_wallet: bool,
    },
    Status {
        payment_hash: String,
        #[serde(default)]
        own_wallet: bool,
    },
    BuyExit {
        provider: String,
        bytes: u64,
        price_msat_per_gb: u64,
        max_amount_sat: u64,
        duration_secs: u64,
    },
    SettleExit {
        agreement_id: String,
    },
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct LocalPolicy {
    forward_existing_credit: bool,
    lightning: Option<fips_credit_link::LightningPayout>,
    market: fips_credit_link::MarketPolicy,
    auto_cashout: Option<fips_credit_link::AutoCashout>,
    receiving_rpc_socket: Option<PathBuf>,
    receiving_node_id: Option<String>,
    receiving_network: Option<String>,
}

type Nodes = Mutex<HashMap<PathBuf, Weak<Node>>>;
static NODES: OnceLock<Nodes> = OnceLock::new();
pub(crate) struct Node {
    pub(super) owner: String,
    auto_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    retry_auto: std::sync::atomic::AtomicBool,
    maintenance: OnceLock<tokio::task::AbortHandle>,
    dir: PathBuf,
    network: String,
    store: Arc<Mutex<AccountStore>>,
    key: Keypair,
    link: Arc<CreditLink>,
    mesh: Weak<FipsPrivateMeshRuntime>,
}

fn load_policy(dir: &Path) -> Result<LocalPolicy> {
    let path = dir.join(JOURNAL);
    let policy_path = dir.join(POLICY);
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let policy: LocalPolicy = match options.open(&policy_path) {
        Ok(file) => {
            use std::io::Read;
            let meta = file.metadata()?;
            ensure!(
                meta.is_file() && meta.len() <= 8192,
                "invalid local credit policy"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                ensure!(
                    meta.uid() == std::fs::metadata(&path)?.uid()
                        && meta.mode() & 0o077 == 0
                        && meta.nlink() == 1,
                    "credit policy needs the same owner and private file permissions"
                );
            }
            serde_json::from_reader(file.take(8193))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => LocalPolicy::default(),
        Err(e) => return Err(e.into()),
    };
    Ok(policy)
}

pub(super) async fn bind(
    mesh: &Arc<FipsPrivateMeshRuntime>,
    dir: &Path,
    nsec: &str,
    network: &str,
) -> Result<()> {
    let path = dir.join(JOURNAL);
    if !path.try_exists()? {
        return Ok(());
    }
    let key = key_from_nsec(nsec)?;
    let owner = key.x_only_public_key().0.to_string();
    let store = Arc::new(Mutex::new(AccountStore::open(&path, &owner)?));
    let policy = load_policy(dir)?;
    let handler = Arc::new(Handler(Arc::downgrade(mesh)));
    let link = CreditLink::bind(
        mesh.endpoint.clone(),
        store.clone(),
        key,
        LinkPolicy {
            forward_existing_credit: policy.forward_existing_credit,
            lightning: policy.lightning,
            market: policy.market,
        },
        Some(handler),
    )
    .await
    .map_err(anyhow::Error::msg)?;
    let node = Arc::new(Node {
        owner,
        auto_task: Default::default(),
        retry_auto: Default::default(),
        maintenance: Default::default(),
        dir: dir.to_path_buf(),
        network: network.to_owned(),
        store,
        key,
        link,
        mesh: Arc::downgrade(mesh),
    });
    if let Some(auto) = policy.auto_cashout {
        // An unavailable wallet leaves normal VPN and manual payments usable.
        match node
            .detect_wallet()
            .await
            .and_then(|wallet| node.start_auto(wallet.rpc_socket, auto))
        {
            Ok(()) => {}
            Err(e) => {
                node.retry_auto
                    .store(true, std::sync::atomic::Ordering::Release);
                tracing::warn!("automatic credit cash-out waiting for receiving wallet: {e}");
            }
        }
    }
    let weak = Arc::downgrade(&node);
    let maintenance = tokio::spawn(async move {
        let mut cursor = 0usize;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            let Some(node) = weak.upgrade() else { break };
            let Ok(ids) = node.recoverable_closures() else {
                continue;
            };
            if node.retry_auto.load(std::sync::atomic::Ordering::Acquire)
                && let Ok(policy) = load_policy(&node.dir)
                && let Some(auto) = policy.auto_cashout
                && let Ok(wallet) = node.detect_wallet().await
            {
                // Recheck after detection so a stop racing this retry wins.
                if let Ok(mut task) = node.auto_task.lock()
                    && node
                        .retry_auto
                        .swap(false, std::sync::atomic::Ordering::AcqRel)
                {
                    #[cfg(unix)]
                    if let Ok(handle) = node.link.start_auto_cashout(wallet.rpc_socket, auto) {
                        *task = Some(handle);
                    }
                    #[cfg(not(unix))]
                    let _ = (&mut task, wallet, auto);
                }
            }
            node.net_reciprocal(cursor).await;
            cursor = cursor.wrapping_add(1);
            if !ids.is_empty() {
                let count = ids.len().min(4);
                for i in 0..count {
                    let _ = node.settle_exit(&ids[(cursor + i) % ids.len()]).await;
                }
            }
        }
    });
    let _ = node.maintenance.set(maintenance.abort_handle());
    mesh.credit
        .set(node.clone())
        .map_err(|_| anyhow!("credit service already active"))?;
    let mut nodes = NODES
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| anyhow!("wallet service unavailable"))?;
    nodes.retain(|_, weak| weak.strong_count() > 0);
    nodes.insert(dir.canonicalize()?, Arc::downgrade(&node));
    Ok(())
}

struct Handler(Weak<FipsPrivateMeshRuntime>);
impl ServiceHandler for Handler {
    fn handle(
        &self,
        peer: &str,
        request: ServiceRequest,
    ) -> std::result::Result<ControlMessage, String> {
        self.process(peer, request).map_err(|e| e.to_string())
    }
}
impl Handler {
    fn process(&self, peer: &str, request: ServiceRequest) -> Result<ControlMessage> {
        let mesh = self.0.upgrade().context("exit stopped")?;
        let node = mesh.credit.get().context("credit service starting")?;
        let live = mesh
            .credit_policy
            .lock()
            .map_err(|_| anyhow!("exit policy unavailable"))?;
        let mut store = node
            .store
            .lock()
            .map_err(|_| anyhow!("credit account unavailable"))?;
        let now = unix_timestamp();
        match request {
            ServiceRequest::Usage { agreement_id } => {
                let units = mesh.mesh.load().seal_credit_upload(peer, &agreement_id)?;
                Ok(ControlMessage::Usage {
                    agreement_id,
                    units,
                })
            }
            ServiceRequest::Terms(terms) => {
                let ip = live
                    .as_ref()
                    .context("seller egress unavailable")?
                    .verify(peer, &terms)?;
                mesh.mesh
                    .load()
                    .check_credit_exit(&node.owner, ip, &terms)?;
                Ok(ControlMessage::Offer(
                    Controller::new(&mut store, &node.key)?.offer(terms, now)?,
                ))
            }
            ServiceRequest::Control(ControlMessage::Acceptance(acceptance)) => {
                let terms = &acceptance.payload;
                let ip = live
                    .as_ref()
                    .context("seller egress unavailable")?
                    .verify(peer, terms)?;
                let mut next = (**mesh.mesh.load()).clone();
                next.check_credit_exit(&node.owner, ip, terms)?;
                let mut controller = Controller::new(&mut store, &node.key)?;
                let offer = controller.offer(terms.clone(), now)?;
                let opened = controller.open(&offer, &acceptance, now)?;
                if let Some(allowance) = opened.allowance {
                    next.install_credit_exit(&node.owner, ip, allowance)?;
                    mesh.publish_mesh(next);
                } else {
                    ensure!(!opened.grant.closed, "agreement is closed");
                    next.credit_upload_units(peer, &terms.id)?;
                }
                Ok(ControlMessage::Offer(offer))
            }
            ServiceRequest::Control(ControlMessage::Receipt(r)) => {
                ensure!(r.payload.payer == peer, "wrong payer");
                let already_accepted = store
                    .book()
                    .seller()
                    .accepted_receipt(&r.payload.agreement_id)
                    .is_some_and(|accepted| accepted.payload == r.payload);
                let mut controller = Controller::new(&mut store, &node.key)?;
                if already_accepted {
                    return Ok(ControlMessage::Acknowledgement(
                        controller.receive_receipt(&r, r.payload.cumulative_units)?,
                    ));
                }
                Ok(ControlMessage::Acknowledgement(
                    mesh.mesh
                        .load()
                        .settle_credit_upload(peer, &r, &mut controller)?,
                ))
            }
            ServiceRequest::Control(ControlMessage::NettingProposal(n)) => {
                ensure!(n.payload.left == peer, "wrong netting peer");
                Ok(ControlMessage::NettingAcknowledgement(
                    Controller::new(&mut store, &node.key)?.accept_netting(&n)?,
                ))
            }
            _ => Err(anyhow!("unsupported exit credit request")),
        }
    }
}

pub(crate) async fn execute(dir: &Path, command: Command) -> Result<Value> {
    let node = NODES
        .get()
        .and_then(|nodes| nodes.lock().ok()?.get(&dir.canonicalize().ok()?)?.upgrade());
    let Some(node) = node.filter(|node| node.mesh.strong_count() > 0) else {
        if matches!(command, Command::Balance) {
            return Ok(
                json!({"available":false,"configured":dir.join(JOURNAL).try_exists()?,"earned_credit_sat":null}),
            );
        }
        return Err(anyhow!(
            "enable peer credit and start the FIPS tunnel for this wallet"
        ));
    };
    match command {
        Command::OfferPayout { peer } => {
            node.link
                .offer_payout(&normalize_nostr_pubkey(&peer)?)
                .await
                .map_err(anyhow::Error::msg)?;
            Ok(json!({"offered":true}))
        }
        Command::ConnectWallet => {
            let wallet = node.detect_wallet().await?;
            let policy = load_policy(dir)?;
            Ok(
                json!({"network":wallet.network,"node_id":wallet.node_id,"auto_cashout":policy.auto_cashout}),
            )
        }
        Command::AutoCashout { policy: auto } => {
            let mut local = load_policy(dir)?;
            let wallet = if let Some(settings) = auto.as_ref() {
                settings.validate().map_err(anyhow::Error::msg)?;
                let w = node.detect_wallet().await?;
                local.receiving_rpc_socket = Some(w.rpc_socket.clone());
                local.receiving_node_id = Some(w.node_id.clone());
                local.receiving_network = Some(w.network.clone());
                Some(w)
            } else {
                None
            };
            local.auto_cashout = auto.clone();
            let bytes = serde_json::to_vec_pretty(&local)?;
            // Save authorization before starting any background work. The
            // private wallet IPC serializes configuration changes per account.
            nostr_vpn_core::config::write_private_file_preserving_user_owner(
                &dir.join(POLICY),
                &bytes,
            )?;
            if let (Some(policy), Some(wallet)) = (auto, wallet) {
                node.start_auto(wallet.rpc_socket, policy)?;
            } else {
                node.stop_auto()?
            }
            Ok(json!({"auto_cashout":local.auto_cashout}))
        }
        Command::Balance => {
            let store = node
                .store
                .lock()
                .map_err(|_| anyhow!("credit account unavailable"))?;
            let available = store
                .book()
                .available_claims()
                .try_fold(0u64, |sum, (_, n)| sum.checked_add(n))
                .context("credit balance overflow")?;
            let earnings = store.book().conversion_earnings()?;
            Ok(
                json!({"available":true,"earned_credit_sat":available,"forwarding_fee_sat":earnings.forwarding_fee_sat,
                "terminal_fee_sat":earnings.terminal_fee_sat,"network_fee_msat":earnings.network_fee_msat}),
            )
        }
        Command::Quote { invoice } => {
            let quote = node
                .link
                .quote_invoice(&invoice)
                .await
                .map_err(anyhow::Error::msg)?;
            Ok(
                json!({"source":"earned_credit","recipient_sat":quote.amount_sat,"cost_credit_sat":quote.debit_sat().map_err(anyhow::Error::msg)?,"fee_credit_sat":quote.fee_sat,"quote":quote}),
            )
        }
        Command::Confirm {
            invoice,
            quote,
            own_wallet,
        } => {
            let state = if own_wallet {
                #[cfg(not(unix))]
                return Err(anyhow!(
                    "receiving Core Lightning needs a local Unix socket"
                ));
                #[cfg(unix)]
                node.link
                    .confirm_cashout(&invoice, &quote, &node.detect_wallet().await?.rpc_socket)
                    .await
            } else {
                node.link.confirm_invoice(&invoice, &quote).await
            }
            .map_err(anyhow::Error::msg)?;
            Ok(json!({"source":"earned_credit","payment_hash":quote.payment_hash,"state":state}))
        }
        Command::Status {
            payment_hash,
            own_wallet,
        } => {
            {
                let store = node
                    .store
                    .lock()
                    .map_err(|_| anyhow!("credit account unavailable"))?;
                if store.book().outgoing_redemption(&payment_hash).is_none() {
                    return Ok(
                        json!({"source":"earned_credit","payment_hash":payment_hash,"state":"unsubmitted"}),
                    );
                }
            }
            let state = if own_wallet {
                #[cfg(not(unix))]
                return Err(anyhow!(
                    "receiving Core Lightning needs a local Unix socket"
                ));
                #[cfg(unix)]
                node.link
                    .resume_cashout(&payment_hash, &node.detect_wallet().await?.rpc_socket)
                    .await
            } else {
                node.link.resume_invoice(&payment_hash).await
            }
            .map_err(anyhow::Error::msg)?;
            Ok(json!({"source":"earned_credit","payment_hash":payment_hash,"state":state}))
        }
        Command::BuyExit {
            provider,
            bytes,
            price_msat_per_gb,
            max_amount_sat,
            duration_secs,
        } => {
            node.buy_exit(
                provider,
                bytes,
                price_msat_per_gb,
                max_amount_sat,
                duration_secs,
            )
            .await
        }
        Command::SettleExit { agreement_id } => node.settle_exit(&agreement_id).await,
    }
}

pub(super) struct BuyerMeter {
    agreement_id: String,
    source: IpAddr,
    units: u64,
    max_units: u64,
}
impl BuyerMeter {
    pub(super) fn observe(&mut self, packet: &[u8]) {
        if self.units < self.max_units
            && nostr_vpn_core::fips_mesh::FipsMeshRuntime::credit_upload_packet(self.source, packet)
        {
            self.units = self
                .units
                .saturating_add(packet.len() as u64)
                .min(self.max_units);
        }
    }
}

impl Drop for FipsPrivateMeshRuntime {
    fn drop(&mut self) {
        if let Some(node) = self.credit.take() {
            if let Some(task) = node.maintenance.get() {
                task.abort()
            }
            let _ = node.stop_auto();
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Ok(task) = self.auto_task.get_mut()
            && let Some(task) = task.take()
        {
            task.abort();
        }
    }
}

impl Node {
    async fn detect_wallet(&self) -> Result<ConnectedWallet> {
        #[cfg(unix)]
        {
            let policy = load_policy(&self.dir)?;
            let wallet = tokio::task::spawn_blocking(move || {
                fips_credit_link::wallet::detect_wallet(policy.receiving_rpc_socket.as_deref())
            })
            .await?
            .map_err(anyhow::Error::msg)?;
            ensure!(
                policy
                    .receiving_node_id
                    .as_deref()
                    .is_none_or(|id| id == wallet.node_id)
                    && policy
                        .receiving_network
                        .as_deref()
                        .is_none_or(|network| network == wallet.network),
                "receiving wallet identity has changed"
            );
            Ok(wallet)
        }
        #[cfg(not(unix))]
        Err(anyhow!(
            "receiving Core Lightning needs a local Unix socket"
        ))
    }
    fn stop_auto(&self) -> Result<()> {
        self.retry_auto
            .store(false, std::sync::atomic::Ordering::Release);
        if let Some(task) = self
            .auto_task
            .lock()
            .map_err(|_| anyhow!("automation unavailable"))?
            .take()
        {
            task.abort();
        }
        Ok(())
    }
    fn start_auto(&self, socket: PathBuf, policy: fips_credit_link::AutoCashout) -> Result<()> {
        #[cfg(not(unix))]
        {
            let _ = (socket, policy);
            return Err(anyhow!(
                "receiving Core Lightning needs a local Unix socket"
            ));
        }
        #[cfg(unix)]
        {
            let mut task = self
                .auto_task
                .lock()
                .map_err(|_| anyhow!("automation unavailable"))?;
            let next = self
                .link
                .start_auto_cashout(socket, policy)
                .map_err(anyhow::Error::msg)?;
            self.retry_auto
                .store(false, std::sync::atomic::Ordering::Release);
            if let Some(old) = task.replace(next) {
                old.abort();
            }
            Ok(())
        }
    }
    async fn net_reciprocal(&self, cursor: usize) {
        let peers = {
            let Ok(store) = self.store.try_lock() else {
                return;
            };
            let book = store.book();
            let claims = book
                .available_claims()
                .map(|(a, _)| &a.payer)
                .collect::<std::collections::BTreeSet<_>>();
            book.available_debts()
                .filter(|(a, _)| claims.contains(&a.provider))
                .map(|(a, _)| &a.provider)
                .chain(book.pending_nettings().map(|n| &n.right))
                .filter(|peer| self.owner.as_str() < peer.as_str())
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        };
        for i in 0..peers.len().min(4) {
            let peer = &peers[(cursor + i) % peers.len()];
            let Some(proposal) = self.store.try_lock().ok().and_then(|mut store| {
                Controller::new(&mut store, &self.key)
                    .ok()?
                    .propose_netting(peer)
                    .ok()
                    .flatten()
            }) else {
                continue;
            };
            let request =
                ServiceRequest::Control(ControlMessage::NettingProposal(proposal.clone()));
            if let Ok(ControlMessage::NettingAcknowledgement(ack)) =
                self.link.service_call(peer, request).await
                && ack.payload == proposal.payload
                && let Ok(mut store) = self.store.try_lock()
                && let Ok(mut c) = Controller::new(&mut store, &self.key)
            {
                let _ = c.finish_netting(&ack);
            }
        }
    }

    fn recoverable_closures(&self) -> Result<Vec<String>> {
        let mesh = self.mesh.upgrade().context("tunnel stopped")?;
        let meters = mesh
            .paid_route_accounting
            .lock()
            .map_err(|_| anyhow!("local meter unavailable"))?;
        let store = self
            .store
            .lock()
            .map_err(|_| anyhow!("credit account unavailable"))?;
        let buyer = store.book().buyer();
        let now = unix_timestamp();
        let mut ids = meters
            .credit_uploads
            .values()
            .filter(|m| {
                m.units == m.max_units
                    || buyer
                        .agreement(&m.agreement_id)
                        .is_some_and(|a| a.expires_at <= now)
            })
            .map(|m| m.agreement_id.clone())
            .collect::<Vec<_>>();
        ids.extend(
            buyer
                .pending_receipts()
                .filter(|r| {
                    buyer
                        .agreement(&r.agreement_id)
                        .is_some_and(|a| a.service == SERVICE)
                })
                .map(|r| r.agreement_id.clone()),
        );
        ids.sort_unstable();
        ids.dedup();
        Ok(ids)
    }

    async fn buy_exit(
        &self,
        provider: String,
        bytes: u64,
        price: u64,
        max_sat: u64,
        duration: u64,
    ) -> Result<Value> {
        let provider = normalize_nostr_pubkey(&provider)?;
        let mesh = self.mesh.upgrade().context("tunnel stopped")?;
        let key = super::participant_pubkey_bytes(&provider).context("invalid provider")?;
        let ip = tunnel_address(&self.network, &self.owner)?;
        ensure!(
            (1..=3600).contains(&duration) && bytes > 0,
            "invalid duration or byte limit"
        );
        let now = unix_timestamp();
        let resource = format!("internet-exit-upload:{ip}");
        let mut terms = Agreement {
            id: uuid::Uuid::new_v4().simple().to_string(),
            payer: self.owner.clone(),
            provider: provider.clone(),
            service: SERVICE.into(),
            resource: resource.clone(),
            max_units: bytes,
            price_sat: price,
            price_per_units: PRICE_DENOMINATOR,
            max_amount_sat: max_sat,
            created_at: now,
            expires_at: now.checked_add(duration).context("invalid expiry")?,
        };
        terms.max_amount_sat = terms.amount_for(bytes)?;
        ensure!(
            terms.max_amount_sat <= max_sat,
            "buy ceiling below quoted service cost"
        );
        let request = ServiceRequest::Terms(terms.clone());
        let ControlMessage::Offer(offer) = self
            .link
            .service_call(&provider, request)
            .await
            .map_err(anyhow::Error::msg)?
        else {
            return Err(anyhow!("expected provider offer"));
        };
        ensure!(offer.payload == terms, "seller changed requested terms");
        let acceptance = {
            let mut meters = mesh
                .paid_route_accounting
                .lock()
                .map_err(|_| anyhow!("local meter unavailable"))?;
            ensure!(
                !meters.credit_uploads.contains_key(&key) && meters.credit_uploads.len() < 128,
                "another credit purchase is active"
            );
            let intent = PurchaseIntent {
                provider: &provider,
                service: SERVICE,
                resource: &resource,
                units: bytes,
                max_price_sat: price,
                price_per_units: PRICE_DENOMINATOR,
                max_amount_sat: max_sat,
                max_duration_secs: duration,
            };
            let mut store = self
                .store
                .lock()
                .map_err(|_| anyhow!("credit account unavailable"))?;
            let acceptance = Controller::new(&mut store, &self.key)?.accept_offer(
                &offer,
                &intent,
                unix_timestamp(),
            )?;
            meters.credit_uploads.insert(
                key,
                BuyerMeter {
                    agreement_id: terms.id.clone(),
                    source: ip,
                    units: 0,
                    max_units: bytes,
                },
            );
            acceptance
        };
        let result = self
            .link
            .service_call(
                &provider,
                ServiceRequest::Control(ControlMessage::Acceptance(acceptance)),
            )
            .await;
        let state = match result {
            Ok(ControlMessage::Offer(opened)) if opened == offer => "open",
            _ => "pending",
        };
        Ok(
            json!({"agreement_id":terms.id,"max_upload_bytes":bytes,"max_credit_sat":terms.max_amount_sat,"state":state}),
        )
    }

    async fn settle_exit(&self, id: &str) -> Result<Value> {
        let mesh = self.mesh.upgrade().context("tunnel stopped")?;
        let (terms, signed_units) = {
            let store = self
                .store
                .lock()
                .map_err(|_| anyhow!("credit account unavailable"))?;
            let buyer = store.book().buyer();
            let terms = buyer.agreement(id).context("unknown purchase")?.clone();
            ensure!(terms.service == SERVICE, "wrong service");
            (
                terms,
                buyer
                    .authorized_receipt(id)
                    .filter(|r| r.final_receipt)
                    .map(|r| r.cumulative_units),
            )
        };
        let key = super::participant_pubkey_bytes(&terms.provider).context("invalid provider")?;
        let units = if let Some(units) = signed_units {
            units
        } else {
            let reply = self
                .link
                .service_call(
                    &terms.provider,
                    ServiceRequest::Usage {
                        agreement_id: id.into(),
                    },
                )
                .await
                .map_err(anyhow::Error::msg)?;
            let ControlMessage::Usage {
                agreement_id,
                units,
            } = reply
            else {
                return Err(anyhow!("expected final meter"));
            };
            ensure!(agreement_id == id, "wrong agreement meter");
            let meters = mesh
                .paid_route_accounting
                .lock()
                .map_err(|_| anyhow!("local meter unavailable"))?;
            let meter = meters
                .credit_uploads
                .get(&key)
                .context("local upload evidence unavailable")?;
            ensure!(
                meter.agreement_id == id && units <= meter.units,
                "seller meter exceeds locally observed upload"
            );
            units
        };
        let receipt = {
            let mut store = self
                .store
                .lock()
                .map_err(|_| anyhow!("credit account unavailable"))?;
            Controller::new(&mut store, &self.key)?.receipt(id, units, true)?
        };
        let result = self
            .link
            .service_call(
                &terms.provider,
                ServiceRequest::Control(ControlMessage::Receipt(receipt.clone())),
            )
            .await;
        let state = match result {
            Ok(ControlMessage::Acknowledgement(ack)) if ack.payload == receipt.payload => {
                let mut store = self
                    .store
                    .lock()
                    .map_err(|_| anyhow!("credit account unavailable"))?;
                Controller::new(&mut store, &self.key)?.acknowledge(&ack)?;
                drop(store);
                let mut meters = mesh
                    .paid_route_accounting
                    .lock()
                    .map_err(|_| anyhow!("local meter unavailable"))?;
                if meters
                    .credit_uploads
                    .get(&key)
                    .is_some_and(|m| m.agreement_id == id)
                {
                    meters.credit_uploads.remove(&key);
                }
                "settled"
            }
            _ => "pending",
        };
        Ok(
            json!({"agreement_id":id,"upload_bytes":units,"charged_credit_sat":terms.amount_for(units)?,"state":state}),
        )
    }
}

#[cfg(test)]
#[path = "credit/tests.rs"]
mod tests;
