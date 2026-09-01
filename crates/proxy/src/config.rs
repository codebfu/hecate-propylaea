//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::env;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// IPv4/IPv6 CIDR used to decide when `X-Forwarded-For` may be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl IpCidr {
    pub fn parse(raw: &str) -> Result<Self> {
        let (addr_part, prefix_part) = raw
            .split_once('/')
            .context("CIDR must be in address/prefix form")?;
        let addr: IpAddr = addr_part
            .parse()
            .with_context(|| format!("invalid CIDR address: {addr_part}"))?;
        let prefix_len: u8 = prefix_part
            .parse()
            .with_context(|| format!("invalid CIDR prefix: {prefix_part}"))?;
        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix {
            bail!("CIDR prefix {prefix_len} exceeds max {max_prefix} for {addr}");
        }
        Ok(Self { addr, prefix_len })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(network), IpAddr::V4(addr)) => ipv4_in_prefix(network, addr, self.prefix_len),
            (IpAddr::V6(network), IpAddr::V6(addr)) => ipv6_in_prefix(network, addr, self.prefix_len),
            _ => false,
        }
    }
}

fn ipv4_in_prefix(network: std::net::Ipv4Addr, addr: std::net::Ipv4Addr, prefix_len: u8) -> bool {
    let network_bits = u32::from_be_bytes(network.octets());
    let addr_bits = u32::from_be_bytes(addr.octets());
    if prefix_len == 0 {
        return true;
    }
    let mask = if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    };
    (network_bits & mask) == (addr_bits & mask)
}

fn ipv6_in_prefix(network: std::net::Ipv6Addr, addr: std::net::Ipv6Addr, prefix_len: u8) -> bool {
    let network_bits = u128::from_be_bytes(network.octets());
    let addr_bits = u128::from_be_bytes(addr.octets());
    if prefix_len == 0 {
        return true;
    }
    let mask = if prefix_len >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix_len)
    };
    (network_bits & mask) == (addr_bits & mask)
}

fn default_trusted_proxy_cidrs() -> Vec<IpCidr> {
    [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
    ]
    .into_iter()
    .filter_map(|raw| IpCidr::parse(raw).ok())
    .collect()
}

fn parse_trusted_proxy_cidrs() -> Result<Vec<IpCidr>> {
    match env::var("TRUSTED_PROXY_CIDRS") {
        Ok(raw) if raw.trim().is_empty() => Ok(default_trusted_proxy_cidrs()),
        Ok(raw) => raw
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(IpCidr::parse)
            .collect(),
        Err(_) => Ok(default_trusted_proxy_cidrs()),
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: String,
    pub upstream_hecate_url: String,
    pub api_key_pepper: String,
    pub key_path: PathBuf,
    pub proxy_id_path: PathBuf,
    pub enrollment_token: Option<String>,
    /// Hostname reported to Hecate (enroll/heartbeat). Prefer the host OS name over the container id.
    pub reported_hostname: String,
    pub sync_interval_secs: u64,
    pub heartbeat_interval_secs: u64,
    pub insecure_skip_tls_verify: bool,
    pub cache_enabled: bool,
    pub cache_dir: PathBuf,
    pub cache_max_bytes: u64,
    /// When the TCP peer matches one of these CIDRs, rate limiting uses `X-Forwarded-For`.
    pub trusted_proxy_cidrs: Vec<IpCidr>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let upstream = env::var("UPSTREAM_HECATE_URL")
            .context("UPSTREAM_HECATE_URL is required")?
            .trim_end_matches('/')
            .to_string();
        if upstream.is_empty() {
            bail!("UPSTREAM_HECATE_URL must not be empty");
        }
        validate_upstream_hecate_url(&upstream)?;

        let pepper = env::var("API_KEY_PEPPER").context("API_KEY_PEPPER is required")?;
        if pepper.len() < 16 {
            bail!("API_KEY_PEPPER must be at least 16 characters");
        }

        let insecure_skip_tls_verify = env::var("INSECURE_SKIP_TLS_VERIFY")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if insecure_skip_tls_verify && !cfg!(feature = "dangerous") {
            bail!("INSECURE_SKIP_TLS_VERIFY requires building with --features dangerous");
        }

        Ok(Self {
            bind_addr: env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into()),
            upstream_hecate_url: upstream,
            api_key_pepper: pepper,
            key_path: PathBuf::from(
                env::var("PROXY_KEY_PATH")
                    .unwrap_or_else(|_| "/var/lib/hecate-propylaea/proxy.key".into()),
            ),
            proxy_id_path: PathBuf::from(
                env::var("PROXY_ID_PATH")
                    .unwrap_or_else(|_| "/var/lib/hecate-propylaea/proxy_id".into()),
            ),
            enrollment_token: env::var("PROXY_ENROLLMENT_TOKEN").ok().filter(|s| !s.is_empty()),
            reported_hostname: resolve_reported_hostname(),
            sync_interval_secs: env::var("SYNC_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            heartbeat_interval_secs: env::var("HEARTBEAT_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            insecure_skip_tls_verify,
            cache_enabled: env::var("CACHE_ENABLED")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                .unwrap_or(true),
            cache_dir: PathBuf::from(
                env::var("CACHE_DIR")
                    .unwrap_or_else(|_| "/var/lib/hecate-propylaea/cache".into()),
            ),
            cache_max_bytes: env::var("CACHE_MAX_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4 * 1024 * 1024 * 1024),
            trusted_proxy_cidrs: parse_trusted_proxy_cidrs()?,
        })
    }
}

fn validate_upstream_hecate_url(raw: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(raw).context("UPSTREAM_HECATE_URL is not a valid URL")?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
            let loopback = host == "localhost"
                || host == "127.0.0.1"
                || host == "::1"
                || host == "host.docker.internal"
                || host.ends_with(".localhost");
            if loopback {
                Ok(())
            } else {
                bail!(
                    "UPSTREAM_HECATE_URL must use HTTPS unless the host is loopback or host.docker.internal"
                );
            }
        }
        _ => bail!("UPSTREAM_HECATE_URL must be http or https"),
    }
}

/// Order: host `/etc/hostname` bind-mount, optional `PROPYLAEA_HOSTNAME`, then container hostname.
fn resolve_reported_hostname() -> String {
    if let Some(host) = read_hostname_file(Path::new("/etc/host_hostname")) {
        return host;
    }
    if let Ok(value) = env::var("PROPYLAEA_HOSTNAME") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "propylaea".into())
}

fn read_hostname_file(path: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    let trimmed = contents.lines().next()?.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn read_hostname_file_takes_first_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hostname");
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "hecate-propylaea\nignored").unwrap();
        assert_eq!(
            read_hostname_file(&path).as_deref(),
            Some("hecate-propylaea")
        );
    }

    #[test]
    fn upstream_url_requires_https_off_loopback() {
        validate_upstream_hecate_url("https://hecate.example:18443").unwrap();
        validate_upstream_hecate_url("http://host.docker.internal:8080").unwrap();
        validate_upstream_hecate_url("http://127.0.0.1:8080").unwrap();
        assert!(validate_upstream_hecate_url("http://hecate.example").is_err());
    }

    #[test]
    fn cidr_contains_ipv4() {
        let cidr = IpCidr::parse("172.16.0.0/12").unwrap();
        assert!(cidr.contains("172.18.0.2".parse().unwrap()));
        assert!(!cidr.contains("203.0.113.1".parse().unwrap()));
    }
}
