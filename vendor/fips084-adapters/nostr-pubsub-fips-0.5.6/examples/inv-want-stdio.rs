//! Test-only process boundary for Rust/TypeScript reliable record interop.

use std::io::{self, BufRead, Write};

use fips_tcp::{Config as TcpConfig, ConnectionId, Stack, State};
use nostr::Event;
use nostr_pubsub::VerifiedEvent;
use nostr_pubsub_fips::{FipsInvWantStream, FipsInvWantStreamAction, FipsInvWantStreamOptions};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Command {
    Publish {
        event: Event,
        connected_peers: Vec<String>,
        now_ms: u64,
    },
    Receive {
        source_peer: String,
        bytes: String,
        connected_peers: Vec<String>,
        now_ms: u64,
    },
    TcpListen {
        port: u16,
    },
    TcpInput {
        peer: String,
        bytes: String,
        now_ms: u64,
    },
    TcpPoll {
        now_ms: u64,
    },
    TcpAccept {
        port: u16,
    },
    TcpWrite {
        id: u64,
        bytes: String,
        now_ms: u64,
    },
    TcpRead {
        id: u64,
        max: usize,
        now_ms: u64,
    },
    TcpClose {
        id: u64,
        now_ms: u64,
    },
    TcpAbort {
        id: u64,
    },
    TcpState {
        id: u64,
    },
}

#[derive(Serialize)]
struct Record {
    peer_id: String,
    record: String,
}

#[derive(Serialize)]
struct Outbound {
    peer: String,
    bytes: String,
}

#[derive(Serialize)]
struct Response {
    ok: bool,
    records: Vec<Record>,
    deliveries: Vec<String>,
    result: Value,
    outbound: Vec<Outbound>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[tokio::main]
async fn main() {
    let mut stream = FipsInvWantStream::new(FipsInvWantStreamOptions::default())
        .expect("default stream options");
    let mut tcp = Stack::<String>::new(TcpConfig::default(), 0x55aa_1234_9988_7766);
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let mut response = match line {
            Ok(line) => execute(&mut stream, &mut tcp, &line)
                .await
                .unwrap_or_else(Response::error),
            Err(error) => Response::error(error.to_string()),
        };
        response.outbound = drain_outbound(&mut tcp);
        serde_json::to_writer(&mut stdout, &response).expect("serialize fixture response");
        writeln!(stdout).expect("write fixture response");
        stdout.flush().expect("flush fixture response");
    }
}

async fn execute(
    stream: &mut FipsInvWantStream,
    tcp: &mut Stack<String>,
    line: &str,
) -> Result<Response, String> {
    let command = serde_json::from_str::<Command>(line).map_err(|error| error.to_string())?;
    match command {
        Command::Publish {
            event,
            connected_peers,
            now_ms,
        } => {
            let actions = stream
                .publish(
                    VerifiedEvent::try_from(event).map_err(|error| error.to_string())?,
                    connected_peers,
                    now_ms,
                )
                .map_err(|error| error.to_string())?;
            Ok(Response::actions(actions))
        }
        Command::Receive {
            source_peer,
            bytes,
            connected_peers,
            now_ms,
        } => {
            let actions = stream
                .receive_bytes(
                    &source_peer,
                    &hex::decode(bytes).map_err(|error| error.to_string())?,
                    connected_peers,
                    now_ms,
                )
                .await
                .map_err(|error| error.to_string())?;
            Ok(Response::actions(actions))
        }
        Command::TcpListen { port } => tcp
            .listen(port)
            .map(|()| Response::result(Value::Null))
            .map_err(|error| error.to_string()),
        Command::TcpInput {
            peer,
            bytes,
            now_ms,
        } => tcp
            .input(
                peer,
                &hex::decode(bytes).map_err(|error| error.to_string())?,
                now_ms,
            )
            .map(|()| Response::result(Value::Null))
            .map_err(|error| error.to_string()),
        Command::TcpPoll { now_ms } => {
            tcp.poll(now_ms);
            Ok(Response::result(Value::Null))
        }
        Command::TcpAccept { port } => Ok(Response::result(
            tcp.accept(port).map(ConnectionId::get).into(),
        )),
        Command::TcpWrite { id, bytes, now_ms } => tcp
            .write(
                connection_id(id),
                &hex::decode(bytes).map_err(|error| error.to_string())?,
                now_ms,
            )
            .map(|accepted| Response::result(json!(accepted)))
            .map_err(|error| error.to_string()),
        Command::TcpRead { id, max, now_ms } => tcp
            .read(connection_id(id), max, now_ms)
            .map(|bytes| Response::result(json!(hex::encode(bytes))))
            .map_err(|error| error.to_string()),
        Command::TcpClose { id, now_ms } => tcp
            .close(connection_id(id), now_ms)
            .map(|()| Response::result(Value::Null))
            .map_err(|error| error.to_string()),
        Command::TcpAbort { id } => tcp
            .abort(connection_id(id))
            .map(|()| Response::result(Value::Null))
            .map_err(|error| error.to_string()),
        Command::TcpState { id } => Ok(Response::result(
            tcp.state(connection_id(id))
                .map(state_name)
                .map_or(Value::Null, Value::from),
        )),
    }
}

impl Response {
    fn actions(actions: Vec<FipsInvWantStreamAction>) -> Self {
        let mut records = Vec::new();
        let mut deliveries = Vec::new();
        for action in actions {
            match action {
                FipsInvWantStreamAction::Send { peer_id, record } => records.push(Record {
                    peer_id,
                    record: hex::encode(record),
                }),
                FipsInvWantStreamAction::Deliver(event) => {
                    deliveries.push(event.event.as_event().id.to_hex());
                }
            }
        }
        Self {
            ok: true,
            records,
            deliveries,
            result: Value::Null,
            outbound: Vec::new(),
            error: None,
        }
    }

    fn result(result: Value) -> Self {
        Self {
            ok: true,
            records: Vec::new(),
            deliveries: Vec::new(),
            result,
            outbound: Vec::new(),
            error: None,
        }
    }

    fn error(error: String) -> Self {
        Self {
            ok: false,
            records: Vec::new(),
            deliveries: Vec::new(),
            result: Value::Null,
            outbound: Vec::new(),
            error: Some(error),
        }
    }
}

fn connection_id(id: u64) -> ConnectionId {
    ConnectionId::from_raw(id)
}

fn drain_outbound(tcp: &mut Stack<String>) -> Vec<Outbound> {
    tcp.drain_outbound()
        .into_iter()
        .map(|outbound| Outbound {
            peer: outbound.peer,
            bytes: hex::encode(outbound.bytes),
        })
        .collect()
}

fn state_name(state: State) -> &'static str {
    match state {
        State::SynSent => "syn-sent",
        State::SynReceived => "syn-received",
        State::Established => "established",
        State::FinWait1 => "fin-wait-1",
        State::FinWait2 => "fin-wait-2",
        State::CloseWait => "close-wait",
        State::Closing => "closing",
        State::LastAck => "last-ack",
        State::TimeWait => "time-wait",
    }
}
