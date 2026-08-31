//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use hecate_protocol::agent_signing::{
    build_canonical_string, HEADER_AGENT_ID, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP,
};
use rand::RngCore;
use uuid::Uuid;

use crate::crypto::ProxyKeypair;

pub fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn signed_headers(
    keypair: &ProxyKeypair,
    proxy_id: Uuid,
    method: &str,
    path: &str,
    body: &[u8],
) -> HeaderMap {
    let timestamp_ms = chrono::Utc::now().timestamp_millis();
    let nonce = generate_nonce();
    let canonical = build_canonical_string(method, path, body, timestamp_ms, &nonce);
    let signature = keypair.sign(canonical.as_bytes());

    let mut headers = HeaderMap::new();
    insert(&mut headers, HEADER_AGENT_ID, &proxy_id.to_string());
    insert(&mut headers, HEADER_TIMESTAMP, &timestamp_ms.to_string());
    insert(&mut headers, HEADER_NONCE, &nonce);
    insert(&mut headers, HEADER_SIGNATURE, &signature);
    headers
}

fn insert(headers: &mut HeaderMap, name: &str, value: &str) {
    let name = HeaderName::from_bytes(name.as_bytes()).expect("header name");
    let value = HeaderValue::from_str(value).expect("header value");
    headers.insert(name, value);
}
