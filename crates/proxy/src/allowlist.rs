//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;
use hecate_protocol::release_artifacts::{is_release_artifact_path, RELEASE_COMPONENTS};

/// Reject encoded / relative traversal before any allowlist match.
pub fn canonicalize_agent_path(path: &str) -> Result<String, ()> {
    let lower = path.to_ascii_lowercase();
    if path.is_empty()
        || !path.starts_with('/')
        || path.contains('\\')
        || path.contains("//")
        || path.contains("/./")
        || path.contains("..")
        || lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(());
    }
    if path.split('/').any(|segment| segment == "." || segment == "..") {
        return Err(());
    }
    Ok(path.to_string())
}

/// Returns true when the method+path is an agent API route Propylaea may expose.
pub fn is_allowed_agent_route(method: &Method, path: &str) -> bool {
    let Ok(path) = canonicalize_agent_path(path) else {
        return false;
    };
    match (method, path.as_str()) {
        (&Method::POST, "/api/v1/agent/enroll") => true,
        (&Method::GET, "/api/v1/agent/status") => true,
        (&Method::GET, "/api/v1/agent/pull") => true,
        (&Method::POST, "/api/v1/agent/credentials/rotate") => true,
        (&Method::POST, "/api/v1/agent/update-offer") => true,
        (&Method::POST, "/api/v1/agent/results") => true,
        (&Method::POST, "/api/v1/agent/heartbeat") => true,
        (&Method::GET, p) if is_release_artifact_path(p) => true,
        (&Method::GET | &Method::PUT, p)
            if is_command_artifact_path(p) =>
        {
            true
        }
        _ => false,
    }
}

fn is_command_artifact_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/api/v1/agent/commands/") else {
        return false;
    };
    let mut parts = rest.split('/');
    let Some(id) = parts.next() else {
        return false;
    };
    let Some(tail) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && tail == "artifact"
        && uuid::Uuid::parse_str(id).is_ok()
}

pub fn is_enroll_route(method: &Method, path: &str) -> bool {
    method == Method::POST && path == "/api/v1/agent/enroll"
}

pub fn is_release_artifact_route(method: &Method, path: &str) -> bool {
    method == Method::GET && is_release_artifact_path(path)
}

pub fn max_body_bytes(method: &Method, path: &str) -> usize {
    if method == Method::PUT
        && path.starts_with("/api/v1/agent/commands/")
        && path.ends_with("/artifact")
    {
        return hecate_protocol::permissions::DEFAULT_MAX_FILE_BYTES as usize;
    }
    if is_enroll_route(method, path) {
        return 1024 * 1024;
    }
    2 * 1024 * 1024
}

/// Headers Propylaea is allowed to relay upstream.
pub fn is_forwardable_request_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "content-type"
            | "accept"
            | "if-none-match"
            | "x-hecate-agent-id"
            | "x-hecate-timestamp"
            | "x-hecate-nonce"
            | "x-hecate-signature"
    )
}

/// Drop headers that must not be forwarded to Hecate.
pub fn retain_forwardable_request_headers(headers: &mut axum::http::HeaderMap) {
    let drop: Vec<_> = headers
        .keys()
        .filter(|name| !is_forwardable_request_header(name.as_str()))
        .cloned()
        .collect();
    for name in drop {
        headers.remove(name);
    }
}

/// Headers Propylaea may return to agents (no hop-by-hop, cookies, or internal Location).
pub fn is_forwardable_response_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("x-hecate-") {
        return true;
    }
    matches!(
        lower.as_str(),
        "content-type"
            | "etag"
            | "cache-control"
            | "last-modified"
            | "content-disposition"
            | "accept-ranges"
    )
}

pub fn retain_forwardable_response_headers(headers: &mut axum::http::HeaderMap) {
    let drop: Vec<_> = headers
        .keys()
        .filter(|name| !is_forwardable_response_header(name.as_str()))
        .cloned()
        .collect();
    for name in drop {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_accepts_core_agent_routes() {
        assert!(is_allowed_agent_route(
            &Method::GET,
            "/api/v1/agent/pull"
        ));
        assert!(is_allowed_agent_route(
            &Method::PUT,
            "/api/v1/agent/commands/00000000-0000-0000-0000-000000000001/artifact"
        ));
        assert!(!is_allowed_agent_route(&Method::GET, "/mcp"));
        assert!(!is_allowed_agent_route(&Method::GET, "/internal/machines"));
        assert!(!is_allowed_agent_route(&Method::GET, "/api/v1/admin/machines"));
    }

    #[test]
    fn allowlist_covers_every_release_component() {
        for component in RELEASE_COMPONENTS {
            let path = format!("/api/v1/agent/releases/1.2.3/artifact/{component}");
            assert!(
                is_allowed_agent_route(&Method::GET, &path),
                "missing allow for {path}"
            );
        }
        assert!(is_allowed_agent_route(
            &Method::GET,
            "/api/v1/agent/releases/1.2.3/proxmox-artifact"
        ));
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(!is_allowed_agent_route(
            &Method::GET,
            "/api/v1/agent/commands/x/../../../../../internal/commands/00000000-0000-0000-0000-000000000001/artifact"
        ));
        assert!(canonicalize_agent_path("/api/v1/agent/pull/%2e%2e/admin").is_err());
    }

    #[test]
    fn strips_hop_by_hop_and_cookie_response_headers() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("content-type", "application/octet-stream".parse().unwrap());
        headers.insert("set-cookie", "session=1".parse().unwrap());
        headers.insert("location", "http://127.0.0.1/internal".parse().unwrap());
        headers.insert("connection", "close".parse().unwrap());
        headers.insert("x-hecate-nonce", "abc".parse().unwrap());
        retain_forwardable_response_headers(&mut headers);
        assert!(headers.get("content-type").is_some());
        assert!(headers.get("x-hecate-nonce").is_some());
        assert!(headers.get("set-cookie").is_none());
        assert!(headers.get("location").is_none());
        assert!(headers.get("connection").is_none());
    }
}
