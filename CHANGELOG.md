# Changelog

## Unreleased

## 1.1.1 — 2026-11-05

### Fixed

- Ignore a leftover `PROXY_ENROLLMENT_TOKEN` when existing proxy credentials still sync successfully.
- Persist a rotated `proxy.key` only after Hecate accepts re-enrollment (rejected tokens no longer orphan working credentials).
- Add `PROXY_FORCE_REENROLL=1` to force credential rotation when existing credentials are still valid.

### Changed

- Docker image installs `curl` and compose healthchecks for Propylaea/Caddy; Caddy exposes `/caddy-healthz`.

## 1.1.0 — 2026-09-30

### Added

- Three independent per-IP rate-limit quotas: enroll (10/min), allowed (120/min), unrecognized (30/min).
- Report limited client IPs on heartbeat; apply operator unbans from proxy sync.

## 1.0.1 — 2026-09-01

### Fixed

- Rate-limit enroll and routine agent traffic with independent per-client counters so pull/heartbeat traffic cannot block enrollment.
- Resolve the real client IP from `X-Forwarded-For` when the TCP peer is a trusted reverse proxy (Caddy/Docker private ranges by default).
- Check proxy readiness before rate limiting so `503 proxy not ready` retries no longer consume enroll quota.

## 1.0.0 — 2026-08-31

Initial public release.

- Add `forget` command to clear persisted proxy identity and rotate the signing key.
