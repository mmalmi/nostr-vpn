use super::*;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

// The header can be authenticated and correlated before decoding nested JSON.
const MAGIC: &[u8; 4] = b"FPC1";
const HEADER: usize = 13;
const MAX_BYTES: usize = 16_384;
const MAX_ACTIVE: usize = 32;
const MAX_SOURCES: usize = 128;

#[derive(Default)]
pub(super) struct Admission {
    sources: HashMap<String, Source>,
    active: usize,
}
struct Source {
    since: Instant,
    calls: usize,
    active: usize,
}
impl Admission {
    fn enter(&mut self, peer: &str, time: Instant) -> bool {
        if self.active >= MAX_ACTIVE {
            return false;
        }
        if !self.sources.contains_key(peer) && self.sources.len() >= MAX_SOURCES {
            self.sources.retain(|_, s| {
                s.active > 0 || time.duration_since(s.since) < Duration::from_secs(1)
            });
            if self.sources.len() >= MAX_SOURCES {
                return false;
            }
        }
        let source = self.sources.entry(peer.into()).or_insert(Source {
            since: time,
            calls: 0,
            active: 0,
        });
        if time.duration_since(source.since) >= Duration::from_secs(1) {
            source.since = time;
            source.calls = 0;
        }
        if source.calls == 12 || source.active == 3 {
            return false;
        }
        source.active += 1;
        source.calls += 1;
        self.active += 1;
        true
    }
    fn leave(&mut self, peer: &str) {
        if let Entry::Occupied(mut source) = self.sources.entry(peer.into()) {
            source.get_mut().active -= 1;
            self.active -= 1;
        }
    }
}

struct InboundPermit(Arc<CreditLink>, String);
impl Drop for InboundPermit {
    fn drop(&mut self) {
        if let Ok(mut a) = self.0.admission.lock() {
            a.leave(&self.1);
        }
    }
}
struct Pending<'a>(&'a CreditLink, (u64, String));
impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if let Ok(mut p) = self.0.pending.lock() {
            p.remove(&self.1);
        }
    }
}

fn encode(id: u64, reply: bool, message: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::from(*MAGIC);
    bytes.push(u8::from(reply));
    bytes.extend_from_slice(&id.to_be_bytes());
    serde_json::to_writer(&mut bytes, message).map_err(err)?;
    if bytes.len() > MAX_BYTES {
        return Err("credit frame too large".into());
    }
    Ok(bytes)
}

impl CreditLink {
    pub(super) async fn neighbors(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, (Instant, BTreeMap<String, PeerIdentity>)>, String>
    {
        let mut neighbors = self.neighbors.lock().await;
        if neighbors.0.elapsed() >= Duration::from_secs(1) {
            let list = self.endpoint.peers().await.map_err(err)?;
            neighbors.1 = list
                .into_iter()
                .filter(|p| p.connected)
                .filter_map(|p| PeerIdentity::from_npub(&p.npub).ok())
                .map(|p| (p.pubkey().to_string(), p))
                .collect();
            neighbors.0 = Instant::now();
        }
        Ok(neighbors)
    }
    async fn adjacent(&self, peer: &str) -> Result<PeerIdentity, String> {
        self.neighbors()
            .await?
            .1
            .get(peer)
            .copied()
            .ok_or_else(|| "credit peer is not adjacent".into())
    }
    pub(super) async fn call(&self, peer: &str, message: Call) -> Result<Reply, String> {
        let remote = self.adjacent(peer).await?;
        let timeout = match message {
            Call::PayoutOffer | Call::PayoutAt { .. } | Call::Query(_) => 5,
            Call::Service(_) => 10,
            Call::Redeem(_) => 30,
        };
        let id = rand::random();
        let key = (id, peer.to_owned());
        let bytes = encode(id, false, &message)?;
        let (send, recv) = oneshot::channel();
        {
            let mut p = self.pending.lock().map_err(|_| "credit link unavailable")?;
            if p.len() >= MAX_ACTIVE || p.contains_key(&key) {
                return Err("credit link busy".into());
            }
            p.insert(key.clone(), send);
        }
        let _pending = Pending(self, key);
        self.endpoint
            .send_datagram(remote, SERVICE_PORT, SERVICE_PORT, bytes)
            .await
            .map_err(err)?;
        tokio::time::timeout(Duration::from_secs(timeout), recv)
            .await
            .map_err(|_| "credit reply pending")?
            .map_err(|_| "credit reply lost".into())
    }

    pub(super) async fn receive(self: &Arc<Self>, remote: PeerIdentity, bytes: &[u8]) {
        if !(HEADER..=MAX_BYTES).contains(&bytes.len()) || &bytes[..4] != MAGIC {
            return;
        }
        let peer = remote.pubkey().to_string();
        let id = u64::from_be_bytes(bytes[5..HEADER].try_into().unwrap());
        if bytes[4] == 1 {
            let key = (id, peer);
            let Ok(mut pending) = self.pending.lock() else {
                return;
            };
            if pending.contains_key(&key)
                && let Ok(reply) = serde_json::from_slice(&bytes[HEADER..])
                && let Some(tx) = pending.remove(&key)
            {
                let _ = tx.send(reply);
            }
            return;
        }
        if bytes[4] != 0 || self.adjacent(&peer).await.is_err() {
            return;
        }
        if !self
            .admission
            .lock()
            .is_ok_and(|mut a| a.enter(&peer, Instant::now()))
        {
            return;
        }
        let permit = InboundPermit(self.clone(), peer.clone());
        let Ok(message) = serde_json::from_slice(&bytes[HEADER..]) else {
            return;
        };
        let link = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let reply = match message {
                Call::PayoutOffer => link.receive_payout_offer(&peer, 0),
                Call::PayoutAt { fee_sat } => link.receive_payout_offer(&peer, fee_sat),
                Call::Query(query) => link.answer_query(&peer, query).await,
                Call::Redeem(request) => link.redeem(&peer, request).await,
                Call::Service(request) => {
                    let handler = link.handler.clone();
                    let response =
                        tokio::task::spawn_blocking(move || handler?.handle(&peer, request).ok())
                            .await;
                    response
                        .ok()
                        .flatten()
                        .map(Reply::Service)
                        .ok_or_else(|| "service declined".into())
                }
            }
            .unwrap_or(Reply::Declined);
            if let Ok(bytes) = encode(id, true, &reply) {
                let _ = link
                    .endpoint
                    .send_datagram(remote, SERVICE_PORT, SERVICE_PORT, bytes)
                    .await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_admission_releases_active_permits_without_resetting_rate() {
        let mut a = Admission::default();
        let t = Instant::now();
        for _ in 0..3 {
            assert!(a.enter("peer", t));
        }
        assert!(!a.enter("peer", t));
        for _ in 0..3 {
            a.leave("peer");
        }
        for _ in 3..12 {
            assert!(a.enter("peer", t));
            a.leave("peer")
        }
        assert!(!a.enter("peer", t));
        assert!(a.enter("peer", t + Duration::from_secs(1)));
        for i in 1..MAX_ACTIVE {
            assert!(a.enter(&format!("peer-{i}"), t + Duration::from_secs(1)));
        }
        assert!(!a.enter("overflow", t + Duration::from_secs(1)));
    }
}
