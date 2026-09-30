//! Test-only process boundary for Rust/TypeScript FIPS pubsub datagrams.

use std::io::{self, BufRead, Write};

use nostr_pubsub::FipsPubsubWireCodec;
use nostr_pubsub_fips::FIPS_NOSTR_PUBSUB_MAX_FRAME_BYTES;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Command {
    frame: String,
}

#[derive(Serialize)]
struct Response {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    frame: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn main() {
    let codec = FipsPubsubWireCodec::new(FIPS_NOSTR_PUBSUB_MAX_FRAME_BYTES)
        .expect("native FIPS pubsub frame limit");
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let response = line
            .map_err(|error| error.to_string())
            .and_then(|line| {
                serde_json::from_str::<Command>(&line).map_err(|error| error.to_string())
            })
            .and_then(|command| hex::decode(command.frame).map_err(|error| error.to_string()))
            .and_then(|frame| {
                codec
                    .decode_frame(&frame)
                    .map_err(|error| error.to_string())
            })
            .and_then(|message| {
                codec
                    .encode_frame(&message)
                    .map_err(|error| error.to_string())
            })
            .map_or_else(
                |error| Response {
                    ok: false,
                    frame: None,
                    error: Some(error),
                },
                |frame| Response {
                    ok: true,
                    frame: Some(hex::encode(frame)),
                    error: None,
                },
            );
        serde_json::to_writer(&mut stdout, &response).expect("serialize fixture response");
        writeln!(stdout).expect("write fixture response");
        stdout.flush().expect("flush fixture response");
    }
}
