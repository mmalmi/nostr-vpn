//! Provider labels are local presentation, never identity or routing authority.
use std::collections::BTreeMap;

use nostr_sdk::prelude::*;
use nostr_social_graph::{NostrEvent, SocialGraph};

const ADJECTIVES: &[&str] = &[
    "Amber", "Brave", "Bright", "Calm", "Clever", "Coral", "Cosmic", "Curious", "Daring", "Dawn",
    "Gentle", "Golden", "Happy", "Jolly", "Kind", "Lucky", "Lunar", "Merry", "Misty", "Nimble",
    "Noble", "Quiet", "Rapid", "Silver", "Snowy", "Solar", "Starry", "Sunny", "Swift", "Vivid",
    "Warm", "Wild",
];
const ANIMALS: &[&str] = &[
    "Badger", "Bear", "Beaver", "Bison", "Cat", "Crane", "Deer", "Dolphin", "Eagle", "Falcon",
    "Finch", "Fox", "Gecko", "Heron", "Ibex", "Koala", "Lark", "Lemur", "Lynx", "Marten", "Otter",
    "Owl", "Panda", "Puffin", "Raven", "Seal", "Sparrow", "Swan", "Tiger", "Turtle", "Whale",
    "Wolf",
];

pub fn provider_alias(seller: &str) -> String {
    let Ok(key) = PublicKey::parse(seller) else {
        return "Unknown provider".into();
    };
    let bytes = key.to_bytes();
    format!(
        "{} {}",
        ADJECTIVES[usize::from(bytes[0]) % ADJECTIVES.len()],
        ANIMALS[usize::from(bytes[1]) % ANIMALS.len()]
    )
}

/// Build the root's authenticated two-hop graph for labels and quote discovery. This does
/// not expand the stricter direct-follow boundary used for service ratings.
pub fn provider_name_graph(root: &str, events: &[Event], now: u64) -> SocialGraph {
    let mut graph = SocialGraph::new(root);
    let mut latest = BTreeMap::new();
    for event in events
        .iter()
        .filter(|e| matches!(e.kind, Kind::ContactList | Kind::MuteList))
    {
        if event.created_at.as_secs() > now.saturating_add(300) || event.verify().is_err() {
            continue;
        }
        let key = (event.pubkey, event.kind);
        if latest.get(&key).is_none_or(|old: &&Event| {
            event.created_at > old.created_at
                || (event.created_at == old.created_at && event.id < old.id)
        }) {
            latest.insert(key, event);
        }
    }
    for distance in 0..=1 {
        let admitted = latest
            .values()
            .filter(|e| graph.get_follow_distance(&e.pubkey.to_hex()) == distance)
            .copied()
            .collect::<Vec<_>>();
        for e in admitted {
            graph.handle_event(
                &NostrEvent {
                    created_at: e.created_at.as_secs(),
                    content: e.content.clone(),
                    tags: e.tags.iter().map(|t| t.as_slice().to_vec()).collect(),
                    kind: u16::from(e.kind).into(),
                    pubkey: e.pubkey.to_hex(),
                    id: e.id.to_hex(),
                    sig: e.sig.to_string(),
                },
                true,
                1.0,
            );
        }
        graph.recalculate_follow_distances();
    }
    graph
}

/// Pick a signed upload-credit quote from services the buyer is already willing
/// to use. The returned quote is still subject to durable purchase authorization.
#[cfg(feature = "peer-credit")]
pub fn select_exit_credit_offer<'a>(
    owner: &PublicKey,
    events: &[Event],
    offers: &'a [peer_payments::Signed<peer_payments::Agreement>],
    intents: &[peer_payments::PurchaseIntent<'_>],
    now: u64,
) -> Result<Option<&'a peer_payments::Signed<peer_payments::Agreement>>, peer_payments::Error> {
    if intents
        .iter()
        .any(|intent| intent.service != "vpn.exit.upload_bytes")
    {
        return Err(peer_payments::Error::Invalid(
            "unsupported exit credit meter",
        ));
    }
    let root = owner.to_hex();
    let graph = provider_name_graph(&root, events, now);
    peer_payments::discovery::QuotePeers::new(&graph, &root)?
        .select_credit_offer(offers, intents, now)
}

pub fn provider_display_name(
    seller: &str,
    graph: &SocialGraph,
    events: &[Event],
    now: u64,
) -> String {
    let Ok(key) = PublicKey::parse(seller) else {
        return provider_alias(seller);
    };
    let hex = key.to_hex();
    if graph.get_follow_distance(&hex) > 2 || graph.is_overmuted(&hex, 1.0) {
        return provider_alias(seller);
    }
    let profile = events
        .iter()
        .filter(|e| {
            e.kind == Kind::Metadata
                && e.pubkey == key
                && e.created_at.as_secs() <= now.saturating_add(300)
                && e.verify().is_ok()
        })
        .max_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
    let metadata = profile.and_then(|e| serde_json::from_str::<serde_json::Value>(&e.content).ok());
    metadata
        .as_ref()
        .and_then(|m| {
            ["display_name", "name"].iter().find_map(|field| {
                let name = m.get(field)?.as_str()?.trim();
                (!name.is_empty() && !name.chars().any(char::is_control))
                    .then(|| name.chars().take(80).collect())
            })
        })
        .unwrap_or_else(|| provider_alias(seller))
}
