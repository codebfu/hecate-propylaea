# Install Propylaea (without Ansible)

1. Build or pull the image (`make docker-build` or registry `…/hecate/hecate-propylaea:propylaea-master`).
2. Place TLS certs for Caddy (`cert.pem` / `key.pem`).
3. Set env: `UPSTREAM_HECATE_URL`, `API_KEY_PEPPER` (identical to Hecate), and `PROXY_ENROLLMENT_TOKEN` for first start.
4. Run compose with Caddy publishing host port **18443**.
5. In Hecate UI → **Proxies**, approve the new proxy if auto-approve is off.
6. Clear `PROXY_ENROLLMENT_TOKEN` after enroll; identity persists under the data volume.

## Re-enroll an existing proxy

1. In Hecate UI → **Proxies** → open the proxy detail → **Create re-enrollment token**.
2. Set `PROXY_ENROLLMENT_TOKEN` to the one-shot `penr_…` token and restart Propylaea.
3. On startup the proxy regenerates its credential key and calls the standard enroll endpoint with the same `proxy_id`.
4. Clear `PROXY_ENROLLMENT_TOKEN` again after a successful restart.

Lampads: set `server_url` in `config.toml` to `https://propylaea-host:18443` (or keep pointing at Hecate). No re-enroll is required when switching URLs for an already enrolled agent. For a lost agent key or missed rotation, create a machine-bound token from **Machines → agent detail** and run `hecate-lampad enroll` on the host.
