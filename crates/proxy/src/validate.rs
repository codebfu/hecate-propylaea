//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::{HeaderMap, Method, StatusCode};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hecate_protocol::agent::AgentState;
use hecate_protocol::agent_signing::{
    build_canonical_string, HEADER_AGENT_ID, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP,
};
use hecate_protocol::agent::EnrollRequest;
use uuid::Uuid;

use crate::crypto::{hmac_sha256_hex, verify_ed25519};
use crate::state::AppState;

const MAX_CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;

pub fn verify_signed_agent_request(
    state: &AppState,
    method: &Method,
    path: &str,
    body: &[u8],
    headers: &HeaderMap,
) -> Result<(), StatusCode> {
    let agent_id = parse_uuid_header(headers, HEADER_AGENT_ID)?;
    let timestamp_ms = parse_i64_header(headers, HEADER_TIMESTAMP)?;
    let nonce = required_header(headers, HEADER_NONCE)?;
    let signature = required_header(headers, HEADER_SIGNATURE)?;

    let now = chrono::Utc::now().timestamp_millis();
    if (now - timestamp_ms).abs() > MAX_CLOCK_SKEW_MS {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if nonce.is_empty() || nonce.len() > 128 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let Some(agent) = state.agents.get(&agent_id) else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    if agent.state == AgentState::Revoked {
        return Err(StatusCode::FORBIDDEN);
    }

    let canonical = build_canonical_string(method.as_str(), path, body, timestamp_ms, &nonce);
    let message = canonical.as_bytes();
    let verified = verify_ed25519(&agent.credential_pubkey, message, &signature)
        || agent
            .credential_pubkey_previous
            .as_ref()
            .is_some_and(|prev| {
                agent
                    .credential_pubkey_previous_expires_at
                    .is_some_and(|expires| expires > chrono::Utc::now())
                    && !prev.trim().is_empty()
                    && verify_ed25519(prev, message, &signature)
            });

    if !verified {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !state.nonces.insert(agent_id, &nonce) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(())
}

pub fn precheck_enroll(state: &AppState, body: &[u8]) -> Result<(), StatusCode> {
    let request: EnrollRequest =
        serde_json::from_slice(body).map_err(|_| StatusCode::BAD_REQUEST)?;

    if !request.enrollment_token.starts_with("enr_") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let hex_part = &request.enrollment_token[4..];
    if hex_part.len() != 48 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let pk_bytes = BASE64
        .decode(request.public_key.trim())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if pk_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let token_hmac = hmac_sha256_hex(&state.config.api_key_pepper, &request.enrollment_token);
    let Some(token) = state.enrollment_tokens.get(&token_hmac) else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let expires_at = chrono::DateTime::parse_from_rfc3339(&token.expires_at)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if expires_at <= chrono::Utc::now() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if token.used_at.is_some() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    match (token.bound_machine_id, request.agent_id) {
        (Some(bound), Some(agent_id)) if bound != agent_id => {
            return Err(StatusCode::UNAUTHORIZED);
        }
        (Some(_), Some(_)) => {}
        (Some(_), None) => {}
        (None, Some(_)) => return Err(StatusCode::UNAUTHORIZED),
        (None, None) => {}
    }

    Ok(())
}

fn required_header(headers: &HeaderMap, name: &str) -> Result<String, StatusCode> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or(StatusCode::UNAUTHORIZED)
}

fn parse_uuid_header(headers: &HeaderMap, name: &str) -> Result<Uuid, StatusCode> {
    required_header(headers, name)?
        .parse()
        .map_err(|_| StatusCode::UNAUTHORIZED)
}

fn parse_i64_header(headers: &HeaderMap, name: &str) -> Result<i64, StatusCode> {
    required_header(headers, name)?
        .parse()
        .map_err(|_| StatusCode::UNAUTHORIZED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hecate_protocol::agent::EnrollRequest;
    use hecate_protocol::proxy::ProxySyncEnrollmentToken;
    use uuid::Uuid;

    fn sample_token(bound_machine_id: Option<Uuid>) -> ProxySyncEnrollmentToken {
        ProxySyncEnrollmentToken {
            token_hmac: "abc".into(),
            expires_at: "2099-01-01T00:00:00Z".into(),
            used_at: None,
            bound_machine_id,
            bound_proxy_id: None,
        }
    }

    fn sample_request(agent_id: Option<Uuid>) -> EnrollRequest {
        EnrollRequest {
            enrollment_token: format!("enr_{}", "a".repeat(48)),
            agent_id,
            public_key: BASE64.encode([0u8; 32]),
            hostname: "host".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            tags: vec![],
            attestation: serde_json::json!({}),
        }
    }

    #[test]
    fn binding_mismatch_rejected() {
        let bound = Uuid::new_v4();
        let other = Uuid::new_v4();
        let token = sample_token(Some(bound));
        let request = sample_request(Some(other));
        match (token.bound_machine_id, request.agent_id) {
            (Some(b), Some(a)) if b != a => assert_ne!(b, a),
            _ => panic!("expected mismatch"),
        }
    }

    #[test]
    fn unbound_token_rejects_agent_id_in_body() {
        let token = sample_token(None);
        let request = sample_request(Some(Uuid::new_v4()));
        match (token.bound_machine_id, request.agent_id) {
            (None, Some(_)) => {}
            _ => panic!("expected rejection path"),
        }
    }
}
