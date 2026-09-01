//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Hecate Propylaea — edge proxy for agent traffic.

mod allowlist;
mod artifact_cache;
mod cli;
mod client_ip;
mod config;
mod crypto;
mod forward;
mod identity;
mod nonce;
mod signing;
mod state;
mod sync;
mod validate;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use clap::Parser;
use hecate_protocol::agent::{EnrollRequest, EnrollResponse};
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

use crate::cli::{Cli, Commands};
use crate::config::Config;
use crate::identity::{forget_proxy_identity, print_forget_proxy_report, ProxyIdentityPaths};
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    match Cli::parse().resolved_command() {
        Commands::Forget => {
            let report = forget_proxy_identity(&ProxyIdentityPaths::from_env())?;
            print_forget_proxy_report(&report);
            Ok(())
        }
        Commands::Serve => serve().await,
    }
}

async fn serve() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env()?;
    let state = Arc::new(AppState::new(config.clone()).await?);

    {
        let bootstrap = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(error) = sync::bootstrap(bootstrap).await {
                error!(%error, "propylaea bootstrap failed");
            }
        });
    }

    {
        let sync_state = Arc::clone(&state);
        let interval = Duration::from_secs(config.sync_interval_secs);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                if let Err(error) = sync::run_once(Arc::clone(&sync_state)).await {
                    warn!(%error, "sync failed");
                }
            }
        });
    }

    {
        let hb_state = Arc::clone(&state);
        let interval = Duration::from_secs(config.heartbeat_interval_secs);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(error) = sync::heartbeat_once(Arc::clone(&hb_state)).await {
                    warn!(%error, "heartbeat failed");
                }
            }
        });
    }

    // Buffer at most 2 MiB for normal agent routes; command-artifact PUT needs the full
    // DEFAULT_MAX_FILE_BYTES budget and is mounted with an explicit higher limit.
    const DEFAULT_ROUTE_BODY_BYTES: usize = 2 * 1024 * 1024;
    let artifact_body_limit =
        hecate_protocol::permissions::DEFAULT_MAX_FILE_BYTES as usize;

    let app = Router::new()
        .route("/healthz", axum::routing::get(|| async { StatusCode::OK }))
        .route(
            "/api/v1/agent/commands/{command_id}/artifact",
            any(handle_request).layer(DefaultBodyLimit::max(artifact_body_limit)),
        )
        .fallback(any(handle_request))
        .with_state(state)
        .layer(DefaultBodyLimit::max(DEFAULT_ROUTE_BODY_BYTES))
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = config.bind_addr.parse()?;
    info!(%addr, upstream = %config.upstream_hecate_url, "propylaea listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn handle_request(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let path = match allowlist::canonicalize_agent_path(uri.path()) {
        Ok(path) => path,
        Err(()) => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };

    if !allowlist::is_allowed_agent_route(&method, &path) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    if !state.forwarding_enabled() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "proxy not ready (awaiting enrollment/approval or sync)",
        )
            .into_response();
    }

    let client_ip =
        client_ip::resolve_client_ip(&addr, &headers, &state.config.trusted_proxy_cidrs);
    if !state.check_rate_limit(&client_ip, allowlist::is_enroll_route(&method, &path)) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }

    let max_body = allowlist::max_body_bytes(&method, &path);
    if body.len() > max_body {
        return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response();
    }

    let validation = if allowlist::is_enroll_route(&method, &path) {
        validate::precheck_enroll(&state, &body)
    } else {
        validate::verify_signed_agent_request(&state, &method, &path, &body, &headers)
    };

    if let Err(status) = validation {
        return (status, status_message(status)).into_response();
    }

    if allowlist::is_enroll_route(&method, &path) {
        let enroll_request = serde_json::from_slice::<EnrollRequest>(&body).ok();
        let token_hmac = enroll_request.as_ref().map(|request| {
            crate::crypto::hmac_sha256_hex(&state.config.api_key_pepper, &request.enrollment_token)
        });
        match forward::forward_to_upstream_buffered(
            &state,
            method,
            &path,
            uri.query(),
            headers,
            body,
        )
        .await
        {
            Ok(response) => {
                if response.status.is_success() {
                    if let (Some(request), Ok(enrolled)) = (
                        enroll_request.as_ref(),
                        serde_json::from_slice::<EnrollResponse>(&response.body),
                    ) {
                        state.upsert_agent_from_enroll(
                            enrolled.agent_id,
                            &request.public_key,
                            enrolled.state,
                        );
                    }
                    if let Some(token_hmac) = token_hmac {
                        state.enrollment_tokens.remove(&token_hmac);
                    }
                }
                forward::buffered_into_response(response).into_response()
            }
            Err(error) => {
                warn!(%error, "upstream forward failed");
                (StatusCode::BAD_GATEWAY, "upstream error").into_response()
            }
        }
    } else {
        match forward::forward_to_upstream(&state, method, &path, uri.query(), headers, body).await {
            Ok(response) => response.into_response(),
            Err(error) => {
                warn!(%error, "upstream forward failed");
                (StatusCode::BAD_GATEWAY, "upstream error").into_response()
            }
        }
    }
}

fn status_message(status: StatusCode) -> &'static str {
    match status {
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::BAD_REQUEST => "bad request",
        StatusCode::PAYLOAD_TOO_LARGE => "body too large",
        _ => "rejected",
    }
}
