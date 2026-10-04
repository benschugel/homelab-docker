# homelab-docker

Docker Compose stacks running on my Windows desktop (Docker Desktop). This repo is the live working directory, not a copy: each stack runs from its folder here, with its Compose project name pinned so volumes and networks survive moves.

Secrets and generated state stay local and gitignored; every stack ships a `.env.example` (and, where needed, other `*.example` files) showing what to fill in. See each stack's README for details.

| Stack | What it does |
|---|---|
| wazuh/ | Wazuh 4.9 single-node SIEM. Includes a custom UniFi syslog decoder and rules, Sysmon tuning rules, a Home Assistant webhook integration, and a Docker event listener. |
| wazuh-mcp/ | Wazuh MCP server so Claude Code can query alerts and agents. Hardened container: loopback-only, read-only FS, dropped caps, read-only API user. |
| frigate/ | Frigate NVR with a custom TensorRT build for NVIDIA GPU detection. Camera credentials come from env substitution. |
| paperless/ | Paperless-ngx with Postgres, Redis, Gotenberg, and Tika for document management. |

Not included: TLS certs, internal_users.yml, databases, media, model caches, tokens.
