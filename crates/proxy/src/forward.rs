//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::Response;
use bytes::Bytes;
use futures_util::StreamExt;
use tracing::info;

use crate::allowlist;
use crate::artifact_cache;
use crate::state::AppState;

pub struct BufferedForwardResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

pub async fn forward_to_upstream_buffered(
    state: &AppState,
    method: Method,
    path: &str,
    query: Option<&str>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<BufferedForwardResponse> {
    let response = forward_to_upstream(state, method, path, query, headers, body).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .context("read upstream response body")?;
    Ok(BufferedForwardResponse {
        status,
        headers,
        body,
    })
}

pub fn buffered_into_response(response: BufferedForwardResponse) -> Response {
    let mut out = Response::new(Body::from(response.body));
    *out.status_mut() = response.status;
    *out.headers_mut() = response.headers;
    out
}

pub async fn forward_to_upstream(
    state: &AppState,
    method: Method,
    path: &str,
    query: Option<&str>,
    mut headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let path = allowlist::canonicalize_agent_path(path)
        .map_err(|_| anyhow::anyhow!("invalid path"))?;

    if allowlist::is_release_artifact_route(&method, &path) {
        if let Some(response) =
            artifact_cache::serve_or_fill(state, &method, &path, query, headers.clone(), body.clone())
                .await?
        {
            return Ok(response);
        }
    }

    let url = match query {
        Some(q) if !q.is_empty() => {
            format!("{}{}?{}", state.config.upstream_hecate_url, path, q)
        }
        _ => format!("{}{}", state.config.upstream_hecate_url, path),
    };

    allowlist::retain_forwardable_request_headers(&mut headers);
    headers.remove("host");
    headers.remove("content-length");
    headers.remove("transfer-encoding");
    headers.remove("connection");

    if let Some(proxy_id) = state.proxy_id().await {
        headers.insert(
            HeaderName::from_static("x-hecate-proxy-id"),
            HeaderValue::from_str(&proxy_id.to_string())?,
        );
    }

    let mut builder = state.http.request(method, &url);
    for (name, value) in headers.iter() {
        builder = builder.header(name, value);
    }
    builder = builder.body(body);

    let upstream = builder.send().await.context("upstream request")?;
    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
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
    *response.status_mut() = status;
    *response.headers_mut() = response_headers;
    Ok(response)
}

pub fn log_ready(proxy_id: uuid::Uuid) {
    info!(%proxy_id, "propylaea forwarding enabled");
}
