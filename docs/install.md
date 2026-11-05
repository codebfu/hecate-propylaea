# Install Propylaea (without Ansible)

1. Build or pull the image (`make docker-build` or registry `…/hecate/hecate-propylaea:propylaea-master`).
2. Place TLS certs for Caddy (`cert.pem` / `key.pem`).
3. Set env: `UPSTREAM_HECATE_URL`, `API_KEY_PEPPER` (identical to Hecate), and `PROXY_ENROLLMENT_TOKEN` for first start.
4. Run compose with Caddy publishing host port **18443**.
5. In Hecate UI → **Proxies**, approve the new proxy if auto-approve is off.
6. Clear `PROXY_ENROLLMENT_TOKEN` after enroll; identity persists under the data volume.
   Leaving a consumed token in env is safe after this release: Propylaea ignores it when existing credentials still sync. Clear it anyway.

## Forget local proxy identity

To wipe the persisted proxy identity on the host (without calling the server):

```bash
docker compose stop propylaea
docker compose run --rm propylaea forget
```

Or on a bare-metal install:

```bash
hecate-propylaea forget
```

This removes `proxy_id`, rotates `proxy.key`, and disables forwarding until a new enrollment succeeds. Revoke the proxy in the Hecate UI if it should no longer be trusted, then set a fresh `PROXY_ENROLLMENT_TOKEN` and restart.

## Re-enroll an existing proxy

1. In Hecate UI → **Proxies** → open the proxy detail → **Create re-enrollment token**.
2. Set `PROXY_ENROLLMENT_TOKEN` to the one-shot `penr_…` token.
3. Restart Propylaea:
   - If existing credentials still sync, Propylaea **ignores** the token (no key rotation).
   - If sync returns `401`, Propylaea re-enrolls with the token and only then persists the new key.
   - To force rotation while credentials are still valid, also set `PROXY_FORCE_REENROLL=1`.
4. Clear `PROXY_ENROLLMENT_TOKEN` (and `PROXY_FORCE_REENROLL`) after a successful restart.

Lampads: set `server_url` in `config.toml` to `https://propylaea-host:18443` (or keep pointing at Hecate). No re-enroll is required when switching URLs for an already enrolled agent. For a lost agent key or missed rotation, create a machine-bound token from **Machines → agent detail** and run `hecate-lampad enroll` on the host.
