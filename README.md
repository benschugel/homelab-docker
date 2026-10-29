# homelab-docker

Docker Compose stacks running on my Windows desktop (Docker Desktop). This repo is the live working directory, not a copy: each stack runs from its folder here, with its Compose project name pinned so volumes and networks survive moves.

Secrets and generated state stay local and gitignored; every stack ships a `.env.example` (and, where needed, other `*.example` files) showing what to fill in. See each stack's README for details.

| Stack | What it does |
|---|---|
| wazuh/ | Wazuh 4.14 single-node SIEM with a Home Assistant webhook integration and a patched Docker event listener. The UniFi decoder, detection and tuning rules, Sysmon configuration and their tests live in [wazuh-detections](https://github.com/benschugel/wazuh-detections). |
| wazuh-mcp/ | Wazuh MCP server in two hardened containers (read-only FS, dropped caps): a loopback-only instance for Claude Code with active response through its own API user, and an authless, read-only instance for Home Assistant, firewalled to the HA host. |
| frigate/ | Frigate NVR with a custom TensorRT build for NVIDIA GPU detection and a Dockerfile that exports YOLOv9 to ONNX. Camera credentials come from env substitution. |
| uptime-kuma/ | Uptime Kuma status page and alerting for the stacks here and the rest of the LAN. |
| watchtower/ | Nightly image updates for opt-in containers (label-enable mode, so Frigate's local build and the pinned Wazuh stack are never touched), with a heartbeat push to Uptime Kuma after every scan. |
| paperless/ | Paperless-ngx with Postgres, Redis, Gotenberg, and Tika for document management, plus a nightly encrypted export script for Task Scheduler. |

Not included: TLS certs, internal_users.yml, databases, media, model caches, tokens.

## After cloning

`frigate/config/config.yml` is tracked with its `known_plates` values redacted by a git clean filter. The filter is declared in `.gitattributes` but lives in local git config, so register it once per clone or the next commit will carry the real plates:

```
git config filter.redact-plates.clean "sed -E '/^  known_plates:/,/^  [a-z_]+:/ s/^( +- ).*/\1REDACTED/'"
git config filter.redact-plates.smudge cat
git config filter.redact-plates.required true
```
