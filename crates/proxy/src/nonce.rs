//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uuid::Uuid;

const TTL: Duration = Duration::from_secs(5 * 60);

pub struct NonceCache {
    inner: Mutex<HashMap<(Uuid, String), Instant>>,
}

impl NonceCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if the nonce was newly recorded; false if it was a replay.
    pub fn insert(&self, agent_id: Uuid, nonce: &str) -> bool {
        let mut guard = self.inner.lock().expect("nonce cache poisoned");
        let now = Instant::now();
        guard.retain(|_, expires| *expires > now);
        let key = (agent_id, nonce.to_string());
        if guard.contains_key(&key) {
            return false;
        }
        guard.insert(key, now + TTL);
        true
    }
}
