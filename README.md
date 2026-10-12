# homelab-docker

Docker Compose stacks running on my Windows desktop (Docker Desktop). This repo is the live working directory, not a copy: each stack runs from its folder here, with its Compose project name pinned so volumes and networks survive moves.

Secrets and generated state stay local and gitignored; every stack ships a `.env.example` (and, where needed, other `*.example` files) showing what to fill in. See each stack's README for details.

| Stack | What it does |
|---|---|
| wazuh/ | Wazuh 4.14 single-node SIEM. Includes a custom UniFi syslog decoder and rules, Sysmon tuning rules, a Home Assistant webhook integration, and a Docker event listener. |
| wazuh-mcp/ | Wazuh MCP server in two hardened containers (read-only FS, dropped caps): a loopback-only instance for Claude Code with active response through its own API user, and an authless, read-only instance for Home Assistant, firewalled to the HA host. |
| frigate/ | Frigate NVR with a custom TensorRT build for NVIDIA GPU detection and a Dockerfile that exports YOLOv9 to ONNX. Camera credentials come from env substitution. |
| paperless/ | Paperless-ngx with Postgres, Redis, Gotenberg, and Tika for document management, plus a nightly encrypted export script for Task Scheduler. |

Not included: TLS certs, internal_users.yml, databases, media, model caches, tokens.
