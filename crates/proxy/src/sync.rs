//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use hecate_protocol::proxy::{
    paths, ProxyEnrollRequest, ProxyEnrollResponse, ProxyHeartbeatRequest, ProxyState,
    ProxySyncResponse,
};
use tracing::{info, warn};

use crate::allowlist::RateLimitClass;
use crate::crypto::{hmac_sha256_hex, ProxyKeypair};
use crate::forward::log_ready;
use crate::signing::signed_headers;
use crate::state::{AppState, CachedAgent};

pub async fn bootstrap(state: Arc<AppState>) -> Result<()> {
    if state.proxy_id().await.is_none() {
        enroll_if_needed(&state).await?;
        return run_once(state).await;
    }

    let has_token = state.config.enrollment_token.is_some();
    if state.config.force_reenroll {
        if !has_token {
            bail!("PROXY_FORCE_REENROLL requires PROXY_ENROLLMENT_TOKEN");
        }
        try_reenroll(&state).await?;
        return run_once(state).await;
    }

    // Prefer existing credentials whenever they still authenticate.
    // A leftover PROXY_ENROLLMENT_TOKEN must not rotate a working keypair.
    match run_once(Arc::clone(&state)).await {
        Ok(()) => {
            if has_token {
                warn!(
                    "ignoring PROXY_ENROLLMENT_TOKEN; existing proxy credentials synced successfully"
                );
            }
            Ok(())
        }
        Err(error) if has_token && is_unauthorized_sync(&error) => {
            warn!(
                %error,
                "existing proxy credentials rejected; attempting re-enrollment with PROXY_ENROLLMENT_TOKEN"
            );
            try_reenroll(&state).await?;
            run_once(state).await
        }
        Err(error) => Err(error),
    }
}

async fn try_reenroll(state: &AppState) -> Result<()> {
    match reenroll_if_needed(state).await {
        Ok(()) => Ok(()),
        Err(error) if should_reset_identity_for_enroll(&error) => {
            warn!(
                %error,
                "resetting stale proxy identity for fresh enrollment token"
            );
            state.clear_proxy_identity().await?;
            enroll_if_needed(state).await?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn should_reset_identity_for_enroll(error: &anyhow::Error) -> bool {
    let msg = format!("{error:#}");
    msg.contains("proxy_id must not be set for a generic enrollment token")
        || msg.contains("proxy enroll failed: 400 ")
        || msg.contains("proxy enroll failed: 404 ")
        || msg.contains("proxy enroll failed: 401 ")
        || msg.contains("proxy re-enroll token rejected")
}

fn is_unauthorized_sync(error: &anyhow::Error) -> bool {
    let msg = format!("{error:#}");
    msg.contains("proxy sync failed: 401 ")
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

    // Generate the new keypair in memory first. Persist only after Hecate accepts it,
    // otherwise a rejected leftover token would orphan the previous working credentials.
    let new_keypair = ProxyKeypair::generate();
    let body = ProxyEnrollRequest {
        enrollment_token: token,
        proxy_id: Some(proxy_id),
        public_key: new_keypair.public_key_b64(),
        hostname: state.config.reported_hostname.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        attestation: serde_json::json!({}),
    };

    let response = post_proxy_enroll(state, body).await?;
    if response.proxy_id != proxy_id {
        bail!("proxy re-enroll returned a different proxy_id");
    }

    new_keypair.persist_at(&state.config.key_path)?;
    state.replace_keypair(new_keypair).await;
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
        bail!("proxy re-enroll token rejected");
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

    for unban in payload.rate_limit_unbans {
        let class = match unban.class {
            hecate_protocol::proxy::ProxyRateLimitClass::Enroll => RateLimitClass::Enroll,
            hecate_protocol::proxy::ProxyRateLimitClass::Allowed => RateLimitClass::Allowed,
            hecate_protocol::proxy::ProxyRateLimitClass::Unrecognized => {
                RateLimitClass::Unrecognized
            }
        };
        state.clear_rate_limit(&unban.ip, class);
        info!(ip = %unban.ip, class = ?class, "applied rate-limit unban from Hecate");
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
        rate_limits: state.list_limited_rate_limits(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_unauthorized_sync() {
        let err = anyhow::anyhow!(
            "proxy sync failed: 401 Unauthorized {{\"error\":\"unauthorized\"}}"
        );
        assert!(is_unauthorized_sync(&err));
        assert!(!is_unauthorized_sync(&anyhow::anyhow!(
            "proxy sync failed: 500 boom"
        )));
    }

    #[test]
    fn rejected_reenroll_token_triggers_identity_reset_path() {
        let err = anyhow::anyhow!("proxy re-enroll token rejected");
        assert!(should_reset_identity_for_enroll(&err));
    }
}
