//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use dashmap::DashMap;
use hecate_protocol::agent::AgentState;
use hecate_protocol::proxy::ProxySyncEnrollmentToken;
use reqwest::Client;
use uuid::Uuid;

use crate::allowlist::RateLimitClass;
use crate::artifact_cache::ArtifactCache;
use crate::config::Config;
use crate::crypto::ProxyKeypair;
use crate::nonce::NonceCache;

#[derive(Clone)]
pub struct CachedAgent {
    pub credential_pubkey: String,
    pub credential_pubkey_previous: Option<String>,
    pub credential_pubkey_previous_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub state: AgentState,
}

pub struct AppState {
    pub config: Config,
    pub http: Client,
    pub keypair: Arc<tokio::sync::RwLock<ProxyKeypair>>,
    pub proxy_id: Arc<tokio::sync::RwLock<Option<Uuid>>>,
    pub agents: DashMap<Uuid, CachedAgent>,
    pub enrollment_tokens: DashMap<String, ProxySyncEnrollmentToken>,
    pub proxy_enrollment_tokens: DashMap<String, ProxySyncEnrollmentToken>,
    pub nonces: NonceCache,
    pub artifact_cache: ArtifactCache,
    pub rate_limits: DashMap<String, RateWindow>,
    forwarding: AtomicBool,
    pub started_at: Instant,
}

#[derive(Debug, Clone)]
pub struct RateWindow {
    pub window_start: Instant,
    pub enroll_count: u32,
    pub allowed_count: u32,
    pub unrecognized_count: u32,
}

impl RateWindow {
    fn count_mut(&mut self, class: RateLimitClass) -> &mut u32 {
        match class {
            RateLimitClass::Enroll => &mut self.enroll_count,
            RateLimitClass::Allowed => &mut self.allowed_count,
            RateLimitClass::Unrecognized => &mut self.unrecognized_count,
        }
    }

    fn count(&self, class: RateLimitClass) -> u32 {
        match class {
            RateLimitClass::Enroll => self.enroll_count,
            RateLimitClass::Allowed => self.allowed_count,
            RateLimitClass::Unrecognized => self.unrecognized_count,
        }
    }
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self> {
        let keypair = ProxyKeypair::load_or_generate(&config.key_path)?;
        let mut builder = Client::builder()
            .use_rustls_tls()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .pool_idle_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(600));
        if config.insecure_skip_tls_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let http = builder.build()?;

        let proxy_id = if config.proxy_id_path.exists() {
            let raw = std::fs::read_to_string(&config.proxy_id_path)?;
            Some(raw.trim().parse()?)
        } else {
            None
        };

        let artifact_cache = ArtifactCache::new();
        if config.cache_enabled {
            artifact_cache.bootstrap(&config.cache_dir).await?;
        }

        Ok(Self {
            config,
            http,
            keypair: Arc::new(tokio::sync::RwLock::new(keypair)),
            proxy_id: Arc::new(tokio::sync::RwLock::new(proxy_id)),
            agents: DashMap::new(),
            enrollment_tokens: DashMap::new(),
            proxy_enrollment_tokens: DashMap::new(),
            nonces: NonceCache::new(),
            artifact_cache,
            rate_limits: DashMap::new(),
            forwarding: AtomicBool::new(false),
            started_at: Instant::now(),
        })
    }

    pub async fn replace_keypair(&self, keypair: ProxyKeypair) {
        *self.keypair.write().await = keypair;
    }

    pub fn set_forwarding(&self, enabled: bool) {
        self.forwarding.store(enabled, Ordering::SeqCst);
    }

    pub fn forwarding_enabled(&self) -> bool {
        self.forwarding.load(Ordering::SeqCst)
    }

    pub async fn proxy_id(&self) -> Option<Uuid> {
        *self.proxy_id.read().await
    }

    pub async fn set_proxy_id(&self, id: Uuid) -> Result<()> {
        let path = &self.config.proxy_id_path;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if path.exists() || std::fs::symlink_metadata(path).is_ok() {
            let _ = std::fs::remove_file(path);
        }
        {
            use std::io::Write;
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(path)?;
                file.write_all(id.to_string().as_bytes())?;
                file.sync_all()?;
            }
            #[cfg(not(unix))]
            {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)?;
                file.write_all(id.to_string().as_bytes())?;
                file.sync_all()?;
            }
        }
        *self.proxy_id.write().await = Some(id);
        Ok(())
    }

    /// Remove persisted proxy identity and rotate the local signing keypair.
    pub async fn clear_proxy_identity(&self) -> Result<()> {
        let paths = crate::identity::ProxyIdentityPaths {
            key_path: self.config.key_path.clone(),
            proxy_id_path: self.config.proxy_id_path.clone(),
        };
        let report = crate::identity::forget_proxy_identity(&paths)?;
        if report.rotated_key {
            let new_keypair = ProxyKeypair::load(&self.config.key_path)?;
            self.replace_keypair(new_keypair).await;
        }
        *self.proxy_id.write().await = None;
        self.set_forwarding(false);
        Ok(())
    }

    pub fn upsert_agent_from_enroll(
        &self,
        agent_id: Uuid,
        credential_pubkey: &str,
        state: AgentState,
    ) {
        self.agents.insert(
            agent_id,
            CachedAgent {
                credential_pubkey: credential_pubkey.trim().to_string(),
                credential_pubkey_previous: None,
                credential_pubkey_previous_expires_at: None,
                state,
            },
        );
    }

    /// Rate-limit by client IP and class (from TCP peer or trusted `X-Forwarded-For`).
    pub fn check_rate_limit(&self, client_ip: &str, class: RateLimitClass) -> bool {
        const MAX_RATE_ENTRIES: usize = 8192;
        let limit = class.limit();
        let window = Duration::from_secs(60);
        let now = Instant::now();
        if self.rate_limits.len() >= MAX_RATE_ENTRIES {
            self.rate_limits
                .retain(|_, w| now.duration_since(w.window_start) < window);
        }
        if self.rate_limits.len() >= MAX_RATE_ENTRIES && !self.rate_limits.contains_key(client_ip) {
            return false;
        }
        let mut entry = self
            .rate_limits
            .entry(client_ip.to_string())
            .or_insert_with(|| RateWindow {
                window_start: now,
                enroll_count: 0,
                allowed_count: 0,
                unrecognized_count: 0,
            });
        if now.duration_since(entry.window_start) >= window {
            entry.window_start = now;
            entry.enroll_count = 0;
            entry.allowed_count = 0;
            entry.unrecognized_count = 0;
        }
        let count = entry.count_mut(class);
        *count = count.saturating_add(1);
        *count <= limit
    }

    /// Clear one class counter for an IP (operator unban).
    pub fn clear_rate_limit(&self, client_ip: &str, class: RateLimitClass) {
        if let Some(mut entry) = self.rate_limits.get_mut(client_ip) {
            *entry.count_mut(class) = 0;
        }
    }

    /// Entries currently over their class limit (for heartbeat reporting).
    pub fn list_limited_rate_limits(&self) -> Vec<hecate_protocol::proxy::ProxyRateLimitEntry> {
        let window = Duration::from_secs(60);
        let now = Instant::now();
        let started_at = chrono::Utc::now();
        let mut out = Vec::new();
        for item in self.rate_limits.iter() {
            let ip = item.key();
            let entry = item.value();
            if now.duration_since(entry.window_start) >= window {
                continue;
            }
            let elapsed = now.duration_since(entry.window_start);
            let window_started_at = (started_at
                - chrono::Duration::from_std(elapsed).unwrap_or_default())
            .to_rfc3339();
            for class in [
                RateLimitClass::Enroll,
                RateLimitClass::Allowed,
                RateLimitClass::Unrecognized,
            ] {
                let count = entry.count(class);
                let limit = class.limit();
                if count > limit {
                    out.push(hecate_protocol::proxy::ProxyRateLimitEntry {
                        ip: ip.clone(),
                        class: class.as_protocol(),
                        count,
                        limit,
                        window_started_at: window_started_at.clone(),
                    });
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn test_state() -> AppState {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("proxy.key");
        let proxy_id_path = dir.path().join("proxy_id");
        let cache_dir = dir.path().join("cache");
        let config = Config {
            bind_addr: "127.0.0.1:8080".into(),
            upstream_hecate_url: "http://127.0.0.1:8080".into(),
            api_key_pepper: "dev-api-key-pepper-change-me".into(),
            key_path,
            proxy_id_path,
            enrollment_token: None,
            reported_hostname: "test".into(),
            sync_interval_secs: 30,
            heartbeat_interval_secs: 60,
            insecure_skip_tls_verify: false,
            cache_enabled: false,
            cache_dir,
            cache_max_bytes: 1024,
            trusted_proxy_cidrs: vec![],
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(AppState::new(config))
            .unwrap()
    }

    #[test]
    fn enroll_and_allowed_limits_are_independent() {
        let state = test_state();
        let client = "203.0.113.10";

        for _ in 0..120 {
            assert!(state.check_rate_limit(client, RateLimitClass::Allowed));
        }
        assert!(!state.check_rate_limit(client, RateLimitClass::Allowed));

        assert!(state.check_rate_limit(client, RateLimitClass::Enroll));
        assert!(state.check_rate_limit(client, RateLimitClass::Unrecognized));
    }

    #[test]
    fn enroll_limit_is_enforced_separately() {
        let state = test_state();
        let client = "198.51.100.4";

        for _ in 0..10 {
            assert!(state.check_rate_limit(client, RateLimitClass::Enroll));
        }
        assert!(!state.check_rate_limit(client, RateLimitClass::Enroll));
        assert!(state.check_rate_limit(client, RateLimitClass::Allowed));
    }

    #[test]
    fn unrecognized_limit_and_unban() {
        let state = test_state();
        let client = "198.51.100.20";

        for _ in 0..30 {
            assert!(state.check_rate_limit(client, RateLimitClass::Unrecognized));
        }
        assert!(!state.check_rate_limit(client, RateLimitClass::Unrecognized));
        assert_eq!(state.list_limited_rate_limits().len(), 1);

        state.clear_rate_limit(client, RateLimitClass::Unrecognized);
        assert!(state.check_rate_limit(client, RateLimitClass::Unrecognized));
    }
}
