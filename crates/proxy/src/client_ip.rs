//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Resolve the real client IP for rate limiting behind a trusted reverse proxy.

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;

use crate::config::IpCidr;

/// When the TCP peer is a trusted proxy, use the leftmost `X-Forwarded-For` hop.
pub fn resolve_client_ip(
    peer: &SocketAddr,
    headers: &HeaderMap,
    trusted_cidrs: &[IpCidr],
) -> String {
    let peer_ip = peer.ip();
    if trusted_cidrs.iter().any(|cidr| cidr.contains(peer_ip)) {
        if let Some(ip) = parse_forwarded_for(headers) {
            return ip.to_string();
        }
    }
    peer_ip.to_string()
}

fn parse_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    let value = headers.get("x-forwarded-for")?.to_str().ok()?;
    let first = value.split(',').next()?.trim();
    if first.is_empty() {
        return None;
    }
    first.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn cidr_v4(addr: &str, prefix: u8) -> IpCidr {
        IpCidr::parse(&format!("{addr}/{prefix}")).unwrap()
    }

    #[test]
    fn trusted_proxy_uses_leftmost_forwarded_for() {
        let peer: SocketAddr = "172.18.0.2:54321".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.10, 172.18.0.2"),
        );
        let trusted = vec![cidr_v4("172.16.0.0", 12)];
        assert_eq!(
            resolve_client_ip(&peer, &headers, &trusted),
            "203.0.113.10"
        );
    }

    #[test]
    fn untrusted_peer_ignores_forwarded_for() {
        let peer: SocketAddr = "203.0.113.55:1234".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4"),
        );
        let trusted = vec![cidr_v4("172.16.0.0", 12)];
        assert_eq!(
            resolve_client_ip(&peer, &headers, &trusted),
            "203.0.113.55"
        );
    }

    #[test]
    fn trusted_proxy_without_header_falls_back_to_peer() {
        let peer: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let headers = HeaderMap::new();
        let trusted = vec![cidr_v4("127.0.0.0", 8)];
        assert_eq!(resolve_client_ip(&peer, &headers, &trusted), "127.0.0.1");
    }
}
