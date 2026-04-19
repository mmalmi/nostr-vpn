//! Small in-memory websocket relay for nostr-sdk integration tests.

use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::get,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, broadcast, mpsc};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NostrEvent {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u32,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct RelayEventSnapshot {
    pub pubkey: String,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct NostrFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kinds: Option<Vec<u32>>,
    #[serde(rename = "#p", skip_serializing_if = "Option::is_none")]
    p_tags: Option<Vec<String>>,
    #[serde(rename = "#t", skip_serializing_if = "Option::is_none")]
    t_tags: Option<Vec<String>>,
    #[serde(rename = "#d", skip_serializing_if = "Option::is_none")]
    d_tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    since: Option<u64>,
}

impl NostrFilter {
    fn matches(&self, event: &NostrEvent) -> bool {
        if let Some(ids) = &self.ids
            && !ids.contains(&event.id)
        {
            return false;
        }
        if let Some(authors) = &self.authors
            && !authors.contains(&event.pubkey)
        {
            return false;
        }
        if let Some(kinds) = &self.kinds
            && !kinds.contains(&event.kind)
        {
            return false;
        }
        if let Some(p_tags) = &self.p_tags {
            let has_match = event
                .tags
                .iter()
                .any(|t| t.len() >= 2 && t[0] == "p" && p_tags.contains(&t[1]));
            if !has_match {
                return false;
            }
        }
        if let Some(t_tags) = &self.t_tags {
            let has_match = event
                .tags
                .iter()
                .any(|t| t.len() >= 2 && t[0] == "t" && t_tags.contains(&t[1]));
            if !has_match {
                return false;
            }
        }
        if let Some(d_tags) = &self.d_tags {
            let has_match = event
                .tags
                .iter()
                .any(|t| t.len() >= 2 && t[0] == "d" && d_tags.contains(&t[1]));
            if !has_match {
                return false;
            }
        }
        if let Some(since) = self.since
            && event.created_at < since
        {
            return false;
        }
        true
    }
}

struct Subscription {
    filters: Vec<NostrFilter>,
}

struct RelayState {
    events: RwLock<Vec<NostrEvent>>,
    broadcast: broadcast::Sender<NostrEvent>,
}

impl RelayState {
    fn new() -> Self {
        let (broadcast, _) = broadcast::channel(2048);
        Self {
            events: RwLock::new(Vec::new()),
            broadcast,
        }
    }
}

pub struct WsRelay {
    state: Arc<RelayState>,
    addr: Option<SocketAddr>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl WsRelay {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RelayState::new()),
            addr: None,
            shutdown_tx: None,
        }
    }

    pub async fn start(&mut self) -> Result<SocketAddr, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        self.addr = Some(addr);

        let state = self.state.clone();
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        let app = Router::new().route("/", get(ws_handler)).with_state(state);

        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    shutdown_rx.recv().await;
                })
                .await
                .ok();
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        Ok(addr)
    }

    pub fn url(&self) -> Option<String> {
        self.addr.map(|addr| format!("ws://{}", addr))
    }

    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
    }

    #[allow(dead_code)]
    pub async fn events_snapshot(&self) -> Vec<RelayEventSnapshot> {
        self.state
            .events
            .read()
            .await
            .iter()
            .map(|event| RelayEventSnapshot {
                pubkey: event.pubkey.clone(),
                kind: event.kind,
                tags: event.tags.clone(),
                content: event.content.clone(),
            })
            .collect()
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<RelayState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<RelayState>) {
    let (mut sender, mut receiver) = socket.split();

    let subscriptions: Arc<RwLock<HashMap<String, Subscription>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let (tx, mut rx) = mpsc::channel::<String>(1024);
    let mut broadcast_rx = state.broadcast.subscribe();

    let subscriptions_clone = subscriptions.clone();
    let tx_clone = tx.clone();

    let broadcast_task = tokio::spawn(async move {
        while let Ok(event) = broadcast_rx.recv().await {
            let subs = subscriptions_clone.read().await;
            for (sub_id, sub) in subs.iter() {
                if sub.filters.iter().any(|f| f.matches(&event)) {
                    let msg = serde_json::json!(["EVENT", sub_id, event]);
                    let _ = tx_clone.send(msg.to_string()).await;
                }
            }
        }
    });

    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(msg)) = receiver.next().await {
        if let Message::Text(text) = msg
            && let Ok(parsed) = serde_json::from_str::<Vec<serde_json::Value>>(&text)
        {
            if parsed.is_empty() {
                continue;
            }

            match parsed[0].as_str().unwrap_or("") {
                "EVENT" => {
                    if parsed.len() >= 2
                        && let Ok(event) = serde_json::from_value::<NostrEvent>(parsed[1].clone())
                    {
                        let event_id = event.id.clone();
                        state.events.write().await.push(event.clone());
                        let _ = state.broadcast.send(event);

                        let ok_msg = serde_json::json!(["OK", event_id, true, ""]);
                        let _ = tx.send(ok_msg.to_string()).await;
                    }
                }
                "REQ" if parsed.len() >= 3 => {
                    let sub_id = parsed[1].as_str().unwrap_or_default().to_string();
                    let mut filters = Vec::new();

                    for raw_filter in parsed.iter().skip(2) {
                        if let Ok(filter) =
                            serde_json::from_value::<NostrFilter>(raw_filter.clone())
                        {
                            filters.push(filter);
                        }
                    }

                    let events = state.events.read().await;
                    for event in events.iter() {
                        if filters.iter().any(|f| f.matches(event)) {
                            let event_msg = serde_json::json!(["EVENT", &sub_id, event]);
                            let _ = tx.send(event_msg.to_string()).await;
                        }
                    }

                    let eose = serde_json::json!(["EOSE", &sub_id]);
                    let _ = tx.send(eose.to_string()).await;

                    subscriptions
                        .write()
                        .await
                        .insert(sub_id, Subscription { filters });
                }
                "CLOSE" => {
                    if parsed.len() >= 2
                        && let Some(sub_id) = parsed[1].as_str()
                    {
                        subscriptions.write().await.remove(sub_id);
                    }
                }
                _ => {}
            }
        }
    }

    broadcast_task.abort();
    send_task.abort();
}
