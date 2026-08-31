//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use hecate_protocol::proxy::{
    paths, ProxyEnrollRequest, ProxyEnrollResponse, ProxyHeartbeatRequest, ProxyState,
    ProxySyncResponse,
};
use tracing::{info, warn};

use crate::crypto::{hmac_sha256_hex, ProxyKeypair};
use crate::forward::log_ready;
use crate::signing::signed_headers;
use crate::state::{AppState, CachedAgent};

pub async fn bootstrap(state: Arc<AppState>) -> Result<()> {
    if state.proxy_id().await.is_none() {
        enroll_if_needed(&state).await?;
    } else if state.config.enrollment_token.is_some() {
        match reenroll_if_needed(&state).await {
            Ok(()) => {}
            Err(error) if should_reset_identity_for_enroll(&error) => {
                warn!(
                    %error,
                    "resetting stale proxy identity for fresh enrollment token"
                );
                state.clear_proxy_identity().await?;
                enroll_if_needed(&state).await?;
            }
            Err(error) => return Err(error),
        }
    }
    run_once(state).await
}

fn should_reset_identity_for_enroll(error: &anyhow::Error) -> bool {
    let msg = format!("{error:#}");
    msg.contains("proxy_id must not be set for a generic enrollment token")
        || msg.contains("proxy enroll failed: 400 ")
        || msg.contains("proxy enroll failed: 404 ")
        || msg.contains("proxy enroll failed: 401 ")
}

async fn enroll_if_needed(state: &AppState) -> Result<()> {
    let Some(token) = state.config.enrollment_token.clone() else {
        bail!("PROXY_ENROLLMENT_TOKEN required for first enroll (no proxy_id on disk)");
    };

    let keypair = state.keypair.read().await;
    let hostname = state.config.reported_hostname.clone();

    let body = ProxyEnrollRequest {
        enrollment_token: token,
        proxy_id: None,
        public_key: keypair.public_key_b64(),
        hostname,
        version: env!("CARGO_PKG_VERSION").to_string(),
        attestation: serde_json::json!({}),
    };
    drop(keypair);

    post_proxy_enroll(state, body).await?;
    Ok(())
}

async fn reenroll_if_needed(state: &AppState) -> Result<()> {
    let Some(token) = state.config.enrollment_token.clone() else {
        return Ok(());
    };
    let Some(proxy_id) = state.proxy_id().await else {
        return Ok(());
    };

    let token_hmac = hmac_sha256_hex(&state.config.api_key_pepper, &token);
    if let Some(cached) = state.proxy_enrollment_tokens.get(&token_hmac) {
        if let Some(bound) = cached.bound_proxy_id {
            if bound != proxy_id {
                bail!("enrollment token is bound to a different proxy");
            }
        }
    }

    let new_keypair = ProxyKeypair::regenerate_at(&state.config.key_path)?;
    state.replace_keypair(new_keypair).await;

    let keypair = state.keypair.read().await;
    let body = ProxyEnrollRequest {
        enrollment_token: token,
        proxy_id: Some(proxy_id),
        public_key: keypair.public_key_b64(),
        hostname: state.config.reported_hostname.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        attestation: serde_json::json!({}),
    };
    drop(keypair);

    let response = post_proxy_enroll(state, body).await?;
    if response.proxy_id != proxy_id {
        bail!("proxy re-enroll returned a different proxy_id");
    }
    info!(proxy_id = %proxy_id, "proxy re-enrolled with Hecate");
    Ok(())
}

async fn post_proxy_enroll(
    state: &AppState,
    body: ProxyEnrollRequest,
) -> Result<ProxyEnrollResponse> {
    let body_bytes = serde_json::to_vec(&body)?;
    let url = format!("{}{}", state.config.upstream_hecate_url, paths::ENROLL);

    let response = state
        .http
        .post(&url)
        .header("content-type", "application/json")
        .body(body_bytes)
        .send()
        .await
        .context("proxy enroll request")?;

    if response.status().as_u16() == 401 && body.proxy_id.is_some() {
        warn!("proxy re-enroll token rejected; continuing with existing credentials");
        return Ok(ProxyEnrollResponse {
            proxy_id: body.proxy_id.unwrap(),
            state: ProxyState::Active,
        });
    }

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        bail!("proxy enroll failed: {status} {text}");
    }

    let enrolled: ProxyEnrollResponse = response.json().await?;
    if body.proxy_id.is_none() {
        state.set_proxy_id(enrolled.proxy_id).await?;
        info!(
            proxy_id = %enrolled.proxy_id,
            ?enrolled.state,
            "proxy enrolled with Hecate"
        );

        if enrolled.state != ProxyState::Active {
            warn!("proxy pending approval; forwarding disabled until approved and sync succeeds");
            state.set_forwarding(false);
        }
    }

    Ok(enrolled)
}

pub async fn run_once(state: Arc<AppState>) -> Result<()> {
    let Some(proxy_id) = state.proxy_id().await else {
        bail!("proxy not enrolled");
    };

    let keypair = state.keypair.read().await;
    let headers = signed_headers(&keypair, proxy_id, "GET", paths::SYNC, b"");
    drop(keypair);

    let url = format!("{}{}", state.config.upstream_hecate_url, paths::SYNC);

    let mut request = state.http.get(&url);
    for (name, value) in headers.iter() {
        request = request.header(name, value);
    }

    let response = request.send().await.context("proxy sync request")?;
    if response.status().as_u16() == 403 {
        state.set_forwarding(false);
        bail!("proxy sync forbidden (pending approval or revoked)");
    }
    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        bail!("proxy sync failed: {status} {text}");
    }

    let payload: ProxySyncResponse = response.json().await?;

    state.agents.clear();
    for agent in payload.agents {
        let previous_expires = agent
            .credential_pubkey_previous_expires_at
            .as_ref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));
        state.agents.insert(
            agent.agent_id,
            CachedAgent {
                credential_pubkey: agent.credential_pubkey,
                credential_pubkey_previous: agent.credential_pubkey_previous,
                credential_pubkey_previous_expires_at: previous_expires,
                state: agent.state,
            },
        );
    }

    state.enrollment_tokens.clear();
    for token in payload.enrollment_tokens {
        state
            .enrollment_tokens
            .insert(token.token_hmac.clone(), token);
    }

    state.proxy_enrollment_tokens.clear();
    for token in payload.proxy_enrollment_tokens {
        state
            .proxy_enrollment_tokens
            .insert(token.token_hmac.clone(), token);
    }

    state.set_forwarding(true);
    log_ready(proxy_id);
    Ok(())
}

pub async fn heartbeat_once(state: Arc<AppState>) -> Result<()> {
    let Some(proxy_id) = state.proxy_id().await else {
        return Ok(());
    };
    if !state.forwarding_enabled() {
        return Ok(());
    }

    let hostname = state.config.reported_hostname.clone();

    let body = ProxyHeartbeatRequest {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: state.started_at.elapsed().as_secs(),
        hostname,
    };
    let body_bytes = serde_json::to_vec(&body)?;
    let keypair = state.keypair.read().await;
    let headers = signed_headers(
        &keypair,
        proxy_id,
        "POST",
        paths::HEARTBEAT,
        &body_bytes,
    );
    drop(keypair);
    let url = format!("{}{}", state.config.upstream_hecate_url, paths::HEARTBEAT);

    let mut request = state
        .http
        .post(&url)
        .header("content-type", "application/json")
        .body(body_bytes);
    for (name, value) in headers.iter() {
        request = request.header(name, value);
    }

    let response = request.send().await.context("proxy heartbeat")?;
    if response.status().as_u16() == 403 {
        state.set_forwarding(false);
        bail!("proxy heartbeat forbidden");
    }
    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        bail!("proxy heartbeat failed: {status} {text}");
    }
    Ok(())
}
