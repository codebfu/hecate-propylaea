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
    pub count: u32,
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
        let path_id = &self.config.proxy_id_path;
        if path_id.exists() {
            std::fs::remove_file(path_id)?;
        }
        *self.proxy_id.write().await = None;
        let new_keypair = ProxyKeypair::regenerate_at(&self.config.key_path)?;
        self.replace_keypair(new_keypair).await;
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

    /// Rate-limit by real peer IP (never X-Forwarded-For).
    pub fn check_rate_limit(&self, peer_ip: &str, enroll: bool) -> bool {
        const MAX_RATE_ENTRIES: usize = 8192;
        let limit = if enroll { 10 } else { 120 };
        let window = Duration::from_secs(60);
        let now = Instant::now();
        if self.rate_limits.len() >= MAX_RATE_ENTRIES {
            self.rate_limits
                .retain(|_, w| now.duration_since(w.window_start) < window);
        }
        if self.rate_limits.len() >= MAX_RATE_ENTRIES && !self.rate_limits.contains_key(peer_ip) {
            return false;
        }
        let mut entry = self
            .rate_limits
            .entry(peer_ip.to_string())
            .or_insert_with(|| RateWindow {
                window_start: now,
                count: 0,
            });
        if now.duration_since(entry.window_start) >= window {
            entry.window_start = now;
            entry.count = 0;
        }
        entry.count += 1;
        entry.count <= limit
    }
}
