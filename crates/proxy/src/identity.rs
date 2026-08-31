//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Persisted proxy identity paths and local reset helpers.

use std::env;
use std::path::PathBuf;

use anyhow::Result;

use crate::crypto::ProxyKeypair;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyIdentityPaths {
    pub key_path: PathBuf,
    pub proxy_id_path: PathBuf,
}

impl ProxyIdentityPaths {
    pub fn from_env() -> Self {
        Self {
            key_path: PathBuf::from(
                env::var("PROXY_KEY_PATH")
                    .unwrap_or_else(|_| "/var/lib/hecate-propylaea/proxy.key".into()),
            ),
            proxy_id_path: PathBuf::from(
                env::var("PROXY_ID_PATH")
                    .unwrap_or_else(|_| "/var/lib/hecate-propylaea/proxy_id".into()),
            ),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ForgetProxyIdentityReport {
    pub removed_proxy_id: bool,
    pub rotated_key: bool,
    pub had_proxy_id: bool,
}

/// Remove persisted proxy identity and rotate the local signing keypair.
///
/// This does not contact the Hecate server. Revoke the proxy in the UI when it
/// should no longer be trusted.
pub fn forget_proxy_identity(paths: &ProxyIdentityPaths) -> Result<ForgetProxyIdentityReport> {
    let mut report = ForgetProxyIdentityReport::default();
    let had_key = paths.key_path.exists();

    if paths.proxy_id_path.exists() {
        let raw = std::fs::read_to_string(&paths.proxy_id_path)?;
        report.had_proxy_id = !raw.trim().is_empty();
        std::fs::remove_file(&paths.proxy_id_path)?;
        report.removed_proxy_id = true;
    }

    if report.removed_proxy_id || had_key {
        ProxyKeypair::regenerate_at(&paths.key_path)?;
        report.rotated_key = true;
    }

    Ok(report)
}

pub fn print_forget_proxy_report(report: &ForgetProxyIdentityReport) {
    if !report.removed_proxy_id && !report.rotated_key {
        println!("No local proxy identity found; proxy is already unenrolled on this host.");
        return;
    }

    println!("Local proxy identity cleared.");
    if report.removed_proxy_id {
        println!("  - removed proxy id");
    }
    if report.rotated_key {
        println!("  - rotated proxy signing key");
    }

    if report.had_proxy_id {
        println!();
        println!(
            "The proxy was forgotten locally. Revoke it in the Hecate UI if it should no longer access the fleet."
        );
    }

    println!();
    println!("Stop Propylaea, set PROXY_ENROLLMENT_TOKEN to a new penr_… token, then restart.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forget_proxy_identity_removes_id_and_rotates_key() {
        let dir = tempfile::tempdir().unwrap();
        let paths = ProxyIdentityPaths {
            key_path: dir.path().join("proxy.key"),
            proxy_id_path: dir.path().join("proxy_id"),
        };

        ProxyKeypair::load_or_generate(&paths.key_path).unwrap();
        let old_key = std::fs::read(&paths.key_path).unwrap();
        std::fs::write(&paths.proxy_id_path, "550e8400-e29b-41d4-a716-446655440000").unwrap();

        let report = forget_proxy_identity(&paths).unwrap();
        assert!(report.removed_proxy_id);
        assert!(report.rotated_key);
        assert!(report.had_proxy_id);
        assert!(!paths.proxy_id_path.exists());

        let new_key = std::fs::read(&paths.key_path).unwrap();
        assert_ne!(old_key, new_key);
    }
}
