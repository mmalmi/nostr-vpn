//! Peer-only service and invoice requests. Discovery never carries the invoice.
//! Signed service and redemption records are persisted by the application account.
use fips_core::{FipsEndpoint, PeerIdentity};
use peer_payments::redemption::{Redemption, RedemptionProof};
use peer_payments::{AccountStore, Agreement, ControlMessage, DurableState, Keypair, Signed};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::oneshot;

mod carrier;
mod payments;
#[cfg(unix)]
pub mod wallet;
pub use wallet_policy::AutoCashout;
mod wallet_policy;

pub const SERVICE_PORT: u16 = 44_748;
const MAX_HOPS: u8 = 4;
const BUDGET: u8 = 12;

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LinkPolicy {
    pub market: MarketPolicy,
    pub forward_existing_credit: bool,
    pub lightning: Option<LightningPayout>,
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MarketPolicy {
    pub advertise_payout: bool,
    pub forward_fee_sat: u64,
    pub payout_fee_sat: u64,
    pub max_invoice_fee_sat: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightningPayout {
    pub rpc_socket: PathBuf,
    pub max_amount_sat: u64,
    pub max_fee_msat: u64,
    pub max_lifetime_payout_sat: u64,
    pub max_lifetime_fees_msat: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InvoiceQuote {
    pub agreement_id: String,
    pub debtor: String,
    pub payment_hash: String,
    pub amount_sat: u64,
    #[serde(default)]
    pub fee_sat: u64,
    pub expires_at: u64,
}

impl InvoiceQuote {
    pub fn debit_sat(&self) -> Result<u64, String> {
        self.amount_sat
            .checked_add(self.fee_sat)
            .ok_or_else(|| "credit amount overflow".into())
    }
}
fn zero(v: &u64) -> bool {
    *v == 0
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentState {
    Pending,
    Paid,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ServiceRequest {
    Terms(Agreement),
    Control(ControlMessage),
    Usage { agreement_id: String },
}

pub trait ServiceHandler: Send + Sync {
    fn handle(
        &self,
        authenticated_peer: &str,
        request: ServiceRequest,
    ) -> Result<ControlMessage, String>;
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    nonce: u64,
    agreement_id: String,
    amount_sat: u64,
    #[serde(default, skip_serializing_if = "zero")]
    max_fee_sat: u64,
    hops: u8,
    probes: u8,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Call {
    PayoutOffer,
    PayoutAt { fee_sat: u64 },
    Query(Query),
    Redeem(Signed<Redemption>),
    Service(ServiceRequest),
}
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Reply {
    Available,
    Priced { fee_sat: u64 },
    Declined,
    Paid(Signed<RedemptionProof>),
    Service(ControlMessage),
}

pub struct CreditLink {
    endpoint: Arc<FipsEndpoint>,
    store: Arc<Mutex<AccountStore>>,
    key: Keypair,
    policy: LinkPolicy,
    handler: Option<Arc<dyn ServiceHandler>>,
    pending: Mutex<BTreeMap<(u64, String), oneshot::Sender<Reply>>>,
    admission: Mutex<carrier::Admission>,
    neighbors: tokio::sync::Mutex<(Instant, BTreeMap<String, PeerIdentity>)>,
    routes: Mutex<payments::Hints>,
    receiver: std::sync::OnceLock<tokio::task::AbortHandle>,
    announcements: std::sync::OnceLock<tokio::task::AbortHandle>,
}

impl CreditLink {
    pub async fn bind(
        endpoint: Arc<FipsEndpoint>,
        store: Arc<Mutex<AccountStore>>,
        key: Keypair,
        policy: LinkPolicy,
        handler: Option<Arc<dyn ServiceHandler>>,
    ) -> Result<Arc<Self>, String> {
        let owner = key.x_only_public_key().0.to_string();
        if store
            .lock()
            .map_err(|_| "credit account unavailable")?
            .book()
            .owner()
            != owner
            || PeerIdentity::from_npub(endpoint.npub())
                .map_err(err)?
                .pubkey()
                .to_string()
                != owner
        {
            return Err("credit account and endpoint identities differ".into());
        }
        if let Some(p) = &policy.lightning {
            if !cfg!(unix)
                || !p.rpc_socket.is_absolute()
                || p.max_amount_sat > p.max_lifetime_payout_sat
                || p.max_fee_msat > p.max_lifetime_fees_msat
            {
                return Err("invalid local Lightning payout policy".into());
            }
        }
        let input = endpoint
            .register_service_receiver(SERVICE_PORT)
            .await
            .map_err(err)?;
        let link = Arc::new(Self {
            endpoint,
            store,
            key,
            policy,
            handler,
            pending: Mutex::default(),
            admission: Mutex::default(),
            routes: Mutex::default(),
            neighbors: tokio::sync::Mutex::new((
                Instant::now() - Duration::from_secs(5),
                BTreeMap::new(),
            )),
            receiver: std::sync::OnceLock::new(),
            announcements: std::sync::OnceLock::new(),
        });
        let weak = Arc::downgrade(&link);
        let task = tokio::spawn(async move {
            let mut batch = Vec::new();
            while input.recv_batch_into(&mut batch, 16).await.is_some() {
                let Some(link) = weak.upgrade() else { break };
                for packet in batch.drain(..) {
                    if packet.source_port == SERVICE_PORT && packet.destination_port == SERVICE_PORT
                    {
                        link.receive(packet.source_peer, packet.data.as_slice())
                            .await;
                    }
                }
            }
        });
        let _ = link.receiver.set(task.abort_handle());
        if link.policy.market.advertise_payout && link.policy.lightning.is_some() {
            let weak = Arc::downgrade(&link);
            let announcements = tokio::spawn(async move {
                let mut cursor = 0;
                loop {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    let Some(link) = weak.upgrade() else { break };
                    cursor = link.refresh_offers(cursor).await.unwrap_or(cursor);
                }
            });
            let _ = link.announcements.set(announcements.abort_handle());
        }
        Ok(link)
    }

    pub async fn service_call(
        &self,
        peer: &str,
        request: ServiceRequest,
    ) -> Result<ControlMessage, String> {
        match self.call(peer, Call::Service(request)).await? {
            Reply::Service(message) => Ok(message),
            _ => Err("peer declined service request".into()),
        }
    }
}

impl Drop for CreditLink {
    fn drop(&mut self) {
        if let Some(task) = self.announcements.get() {
            task.abort();
        }
        if let Some(task) = self.receiver.get() {
            task.abort();
        }
    }
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn now() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(err)?
        .as_secs())
}
