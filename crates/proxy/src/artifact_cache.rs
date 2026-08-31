//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Content-addressed release-artifact cache with single-flight fill.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use dashmap::DashMap;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, Notify};
use tracing::{info, warn};

use crate::allowlist;
use crate::state::AppState;

const FOLLOWER_WAIT: Duration = Duration::from_secs(120);
const MAX_IF_NONE_MATCH: usize = 8;

#[derive(Default)]
pub struct ArtifactCache {
    index: DashMap<String, Vec<String>>,
    inflight: DashMap<String, Arc<Notify>>,
    refcounts: DashMap<String, AtomicU64>,
    last_used: DashMap<String, Instant>,
    bytes_used: AtomicU64,
    fill_lock: Mutex<()>,
}

impl ArtifactCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn bootstrap(&self, cache_dir: &Path) -> Result<()> {
        let blobs = cache_dir.join("blobs");
        if !blobs.exists() {
            tokio::fs::create_dir_all(&blobs).await?;
            return Ok(());
        }
        let mut total = 0u64;
        let mut entries = tokio::fs::read_dir(&blobs).await?;
        while let Some(prefix) = entries.next_entry().await? {
            if !prefix.file_type().await?.is_dir() {
                continue;
            }
            let mut files = tokio::fs::read_dir(prefix.path()).await?;
            while let Some(file) = files.next_entry().await? {
                if !file.file_type().await?.is_file() {
                    continue;
                }
                let name = file.file_name().to_string_lossy().to_string();
                if name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                    let meta = file.metadata().await?;
                    total += meta.len();
                    self.last_used.insert(name, Instant::now());
                }
            }
        }
        self.bytes_used.store(total, Ordering::SeqCst);
        info!(bytes = total, "artifact cache bootstrapped");
        Ok(())
    }
}

pub async fn serve_or_fill(
    state: &AppState,
    method: &Method,
    path: &str,
    query: Option<&str>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Option<Response>> {
    if !state.config.cache_enabled {
        return Ok(None);
    }
    let cache = &state.artifact_cache;

    // Single-flight: wait if another request is filling this path.
    if let Some(notify) = cache.inflight.get(path).map(|e| Arc::clone(e.value())) {
        let waited = tokio::time::timeout(FOLLOWER_WAIT, notify.notified()).await;
        if waited.is_err() {
            return Ok(Some(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [("retry-after", "30")],
                    "artifact fill in progress",
                )
                    .into_response(),
            ));
        }
    }

    let known = cache
        .index
        .get(path)
        .map(|v| v.clone())
        .unwrap_or_default();

    // Leader or post-wait follower: revalidate with If-None-Match.
    let notify = Arc::new(Notify::new());
    let became_leader = {
        let entry = cache
            .inflight
            .entry(path.to_string())
            .or_insert_with(|| Arc::clone(&notify));
        Arc::ptr_eq(entry.value(), &notify)
    };
    if !became_leader {
        // Another leader won the race after we waited; try again next request.
        return Ok(None);
    }

    let result = fill_once(state, method, path, query, headers, body, &known).await;
    cache.inflight.remove(path);
    notify.notify_waiters();
    result
}

async fn fill_once(
    state: &AppState,
    method: &Method,
    path: &str,
    query: Option<&str>,
    mut headers: HeaderMap,
    body: Bytes,
    known: &[String],
) -> Result<Option<Response>> {
    let url = match query {
        Some(q) if !q.is_empty() => {
            format!("{}{}?{}", state.config.upstream_hecate_url, path, q)
        }
        _ => format!("{}{}", state.config.upstream_hecate_url, path),
    };

    allowlist::retain_forwardable_request_headers(&mut headers);
    if !known.is_empty() {
        let joined = known
            .iter()
            .take(MAX_IF_NONE_MATCH)
            .map(|h| format!("\"{h}\""))
            .collect::<Vec<_>>()
            .join(", ");
        if let Ok(value) = HeaderValue::from_str(&joined) {
            headers.insert(HeaderName::from_static("if-none-match"), value);
        }
    }
    if let Some(proxy_id) = state.proxy_id().await {
        headers.insert(
            HeaderName::from_static("x-hecate-proxy-id"),
            HeaderValue::from_str(&proxy_id.to_string())?,
        );
    }

    let mut builder = state.http.request(method.clone(), &url);
    for (name, value) in headers.iter() {
        builder = builder.header(name, value);
    }
    let upstream = builder.body(body).send().await.context("upstream request")?;
    let status = upstream.status();

    if status.as_u16() == 304 {
        if let Some(sha) = known.first() {
            if let Some(response) = serve_blob(state, sha).await? {
                return Ok(Some(response));
            }
        }
        return Ok(Some(
            (StatusCode::SERVICE_UNAVAILABLE, "cached blob missing").into_response(),
        ));
    }

    if !status.is_success() {
        let mut response_headers = HeaderMap::new();
        for (name, value) in upstream.headers().iter() {
            if name.as_str() == "transfer-encoding" || name.as_str() == "content-length" {
                continue;
            }
            response_headers.insert(name.clone(), value.clone());
        }
        allowlist::retain_forwardable_response_headers(&mut response_headers);
        let stream = upstream.bytes_stream().map(|chunk| {
            chunk.map_err(|error| std::io::Error::other(error.to_string()))
        });
        let mut response = Response::new(Body::from_stream(stream));
        *response.status_mut() =
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        *response.headers_mut() = response_headers;
        return Ok(Some(response));
    }

    let etag_sha = upstream
        .headers()
        .get(axum::http::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().trim_matches('"').to_string());
    let content_length = upstream.content_length().unwrap_or(0);

    if content_length > 0
        && !reserve_space(state, content_length).await?
    {
        warn!(content_length, "artifact too large for cache budget; streaming through");
        let stream = upstream.bytes_stream().map(|chunk| {
            chunk.map_err(|error| std::io::Error::other(error.to_string()))
        });
        return Ok(Some(Response::new(Body::from_stream(stream))));
    }

    let tmp = state.config.cache_dir.join(format!(
        "tmp-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    if let Some(parent) = tmp.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)
        .await?;
    let mut hasher = Sha256::new();
    let mut stream = upstream.bytes_stream();
    let mut collected: Vec<Bytes> = Vec::new();
    let mut total = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("upstream body")?;
        total = total.saturating_add(chunk.len() as u64);
        if total > state.config.cache_max_bytes / 4 {
            let _ = tokio::fs::remove_file(&tmp).await;
            warn!("artifact exceeded 25% admission budget; streaming remainder without cache");
            // Fall through: we already buffered some; for simplicity re-fetch is avoided —
            // serve what we have plus remaining stream by concatenating is hard; drop cache.
            collected.push(chunk);
            while let Some(more) = stream.next().await {
                collected.push(more.context("upstream body")?);
            }
            let body = collected.into_iter().flatten().collect::<Vec<u8>>();
            return Ok(Some(
                (
                    StatusCode::OK,
                    [("content-type", "application/octet-stream")],
                    body,
                )
                    .into_response(),
            ));
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
        collected.push(chunk);
    }
    file.flush().await?;
    drop(file);

    let digest = hex::encode(hasher.finalize());
    let Some(etag) = etag_sha.as_ref() else {
        let _ = tokio::fs::remove_file(&tmp).await;
        warn!("upstream artifact response has no ETag; streaming through without cache");
        let body = collected.into_iter().flatten().collect::<Vec<u8>>();
        return Ok(Some(
            (
                StatusCode::OK,
                [("content-type", "application/octet-stream")],
                body,
            )
                .into_response(),
        ));
    };
    if etag != &digest {
        let _ = tokio::fs::remove_file(&tmp).await;
        anyhow::bail!("upstream ETag does not match body sha256");
    }

    let dest = blob_path(&state.config.cache_dir, &digest);
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if !dest.exists() {
        tokio::fs::rename(&tmp, &dest).await?;
        state
            .artifact_cache
            .bytes_used
            .fetch_add(total, Ordering::SeqCst);
    } else {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
    state.artifact_cache.last_used.insert(digest.clone(), Instant::now());
    state
        .artifact_cache
        .index
        .entry(path.to_string())
        .or_default()
        .retain(|h| h != &digest);
    state
        .artifact_cache
        .index
        .entry(path.to_string())
        .or_default()
        .insert(0, digest.clone());

    let body = collected.into_iter().flatten().collect::<Vec<u8>>();
    Ok(Some(
        (
            StatusCode::OK,
            [
                ("content-type", "application/octet-stream"),
                ("etag", &format!("\"{digest}\"")),
            ],
            body,
        )
            .into_response(),
    ))
}

async fn serve_blob(state: &AppState, sha: &str) -> Result<Option<Response>> {
    let path = blob_path(&state.config.cache_dir, sha);
    if !path.exists() {
        return Ok(None);
    }
    state
        .artifact_cache
        .refcounts
        .entry(sha.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::SeqCst);
    state
        .artifact_cache
        .last_used
        .insert(sha.to_string(), Instant::now());
    let bytes = tokio::fs::read(&path).await?;
    state
        .artifact_cache
        .refcounts
        .get(sha)
        .map(|c| c.fetch_sub(1, Ordering::SeqCst));
    Ok(Some(
        (
            StatusCode::OK,
            [
                ("content-type", "application/octet-stream"),
                ("etag", &format!("\"{sha}\"")),
            ],
            bytes,
        )
            .into_response(),
    ))
}

fn blob_path(cache_dir: &Path, sha: &str) -> PathBuf {
    let prefix = sha.get(..2).unwrap_or("00");
    cache_dir.join("blobs").join(prefix).join(sha)
}

async fn reserve_space(state: &AppState, needed: u64) -> Result<bool> {
    let max = state.config.cache_max_bytes;
    if needed > max / 4 {
        return Ok(false);
    }
    let _guard = state.artifact_cache.fill_lock.lock().await;
    let mut used = state.artifact_cache.bytes_used.load(Ordering::SeqCst);
    if used + needed <= max {
        return Ok(true);
    }
    // Evict LRU until enough room.
    let mut entries: Vec<(String, Instant)> = state
        .artifact_cache
        .last_used
        .iter()
        .map(|e| (e.key().clone(), *e.value()))
        .collect();
    entries.sort_by_key(|(_, ts)| *ts);
    for (sha, _) in entries {
        if used + needed <= max {
            break;
        }
        if state
            .artifact_cache
            .refcounts
            .get(&sha)
            .is_some_and(|c| c.load(Ordering::SeqCst) > 0)
        {
            continue;
        }
        let path = blob_path(&state.config.cache_dir, &sha);
        if let Ok(meta) = tokio::fs::metadata(&path).await {
            let _ = tokio::fs::remove_file(&path).await;
            used = used.saturating_sub(meta.len());
            state.artifact_cache.bytes_used.store(used, Ordering::SeqCst);
            state.artifact_cache.last_used.remove(&sha);
            for mut item in state.artifact_cache.index.iter_mut() {
                item.value_mut().retain(|h| h != &sha);
            }
        }
    }
    Ok(used + needed <= max)
}
