# Security notes

- Keep Propylaea and Hecate on the same `API_KEY_PEPPER`; compromise of the pepper allows forging enrollment HMAC prechecks (Hecate still claims tokens).
- Agent enroll precheck rejects bound-token / body `agent_id` mismatches before forwarding to Hecate.
- Do not expose Propylaea management ports; only Caddy HTTPS (`:18443` by default). HTTP port 80 is not published and Caddy has no `:80` listener.
- Rotate / revoke compromised proxies immediately in the Hecate UI (fail closed on sync).
- Nonce cache is in-memory per instance; multi-replica deployments should use sticky sessions or accept a residual replay window until Hecate rejects.
- Never forward or accept `/internal/*` or `/mcp` on this host.
