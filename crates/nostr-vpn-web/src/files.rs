//! HTTP is only the existing browser-to-daemon control boundary. Mesh transfers
//! use the shared FIPS stream service directly.
use super::{ApiError, ApiResult, ServerState};
use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use nostr_vpn_core::file_transfers::{self, FileCommand};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn config(state: &ServerState) -> PathBuf {
    PathBuf::from(state.core.state().config_path)
}
fn bad(error: impl std::fmt::Display) -> ApiError {
    ApiError::bad_request(error.to_string())
}

#[derive(Deserialize)]
pub struct InboxQuery {
    before: Option<String>,
}

pub async fn list(
    State(state): State<ServerState>,
    Query(query): Query<InboxQuery>,
) -> ApiResult<Json<file_transfers::inbox::InboxPage>> {
    Ok(Json(
        file_transfers::inbox::page(&config(&state), query.before.as_deref()).map_err(bad)?,
    ))
}

#[derive(Deserialize)]
pub struct SendQuery {
    npub: String,
    name: String,
}

/// Incomplete HTTP uploads are owned staging only and never become file offers.
struct PendingUpload {
    config: PathBuf,
    path: Option<PathBuf>,
}
impl Drop for PendingUpload {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = file_transfers::discard_staged(&self.config, path);
        }
    }
}

pub async fn send(
    State(state): State<ServerState>,
    Query(query): Query<SendQuery>,
    request: Request,
) -> ApiResult<Json<Value>> {
    static UPLOADS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
    let _permit = UPLOADS
        .try_acquire()
        .map_err(|_| bad("Two files are already uploading. Try again shortly."))?;
    nostr_vpn_core::config::normalize_nostr_pubkey(&query.npub).map_err(bad)?;
    if !file_transfers::valid_filename(&query.name) {
        return Err(bad("Invalid filename"));
    }
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|size| size > file_transfers::MAX_FILE_BYTES) {
        return Err(bad("File is too large"));
    }
    let config = config(&state);
    if !state.core.state().vpn_active {
        return Err(bad("Connect VPN to send files"));
    }
    file_transfers::validate_recipient(&config, &query.npub).map_err(bad)?;
    let (path, output) = file_transfers::create_upload(&config, &query.name).map_err(bad)?;
    let mut cleanup = PendingUpload {
        config: config.clone(),
        path: Some(path.clone()),
    };
    let mut output = tokio::fs::File::from_std(output);
    let mut stream = request.into_body().into_data_stream();
    let mut received = 0_u64;
    while let Some(chunk) = tokio::time::timeout(std::time::Duration::from_secs(60), stream.next())
        .await
        .map_err(|_| bad("File upload stopped. Try again."))?
    {
        let chunk = chunk.map_err(bad)?;
        received = received
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| bad("File is too large"))?;
        if received > file_transfers::MAX_FILE_BYTES {
            return Err(bad("File is too large"));
        }
        output.write_all(&chunk).await.map_err(bad)?;
    }
    if declared.is_some_and(|size| size != received) {
        return Err(bad("File upload was interrupted"));
    }
    output.sync_all().await.map_err(bad)?;
    drop(output);
    let id = file_transfers::enqueue(
        &config,
        FileCommand::Send {
            npub: query.npub,
            paths: vec![path.to_string_lossy().into_owned()],
        },
    )
    .map_err(bad)?;
    cleanup.path = None;
    Ok(Json(json!({ "id": id })))
}

async fn action(state: ServerState, command: FileCommand) -> ApiResult<Json<Value>> {
    let id = file_transfers::enqueue(&config(&state), command).map_err(bad)?;
    Ok(Json(json!({ "id": id })))
}
pub async fn accept(
    State(state): State<ServerState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    action(state, FileCommand::Accept { id }).await
}
pub async fn decline(
    State(state): State<ServerState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    action(state, FileCommand::Decline { id }).await
}
pub async fn cancel(
    State(state): State<ServerState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    action(state, FileCommand::Cancel { id }).await
}
pub async fn resume(
    State(state): State<ServerState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    action(state, FileCommand::Resume { id }).await
}

pub async fn download(
    State(state): State<ServerState>,
    Path((id, index)): Path<(String, usize)>,
) -> ApiResult<Response> {
    let (file, input) = file_transfers::completed_file(&config(&state), &id, index).map_err(bad)?;
    let input = tokio::fs::File::from_std(input);
    let stream = futures::stream::try_unfold(input, |mut file| async move {
        let mut buffer = vec![0_u8; 64 * 1024];
        let length = file.read(&mut buffer).await?;
        if length == 0 {
            return Ok::<_, std::io::Error>(None);
        }
        buffer.truncate(length);
        Ok(Some((buffer, file)))
    });
    let mut response = (StatusCode::OK, Body::from_stream(stream)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&file.size_bytes.to_string()).map_err(bad)?,
    );
    // Percent encoding preserves Unicode filenames without creating response headers.
    let name: String = file
        .name
        .as_bytes()
        .iter()
        .map(|byte| format!("%{byte:02X}"))
        .collect();
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{name}")).map_err(bad)?,
    );
    Ok(response)
}
