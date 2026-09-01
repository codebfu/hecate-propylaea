# Changelog

## 1.0.1 — 2026-09-01

### Fixed

- Rate-limit enroll and routine agent traffic with independent per-client counters so pull/heartbeat traffic cannot block enrollment.
- Resolve the real client IP from `X-Forwarded-For` when the TCP peer is a trusted reverse proxy (Caddy/Docker private ranges by default).
- Check proxy readiness before rate limiting so `503 proxy not ready` retries no longer consume enroll quota.

## 1.0.0 — 2026-08-31

Initial public release.

- Add `forget` command to clear persisted proxy identity and rotate the signing key.
