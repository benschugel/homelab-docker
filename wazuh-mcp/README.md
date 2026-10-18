# wazuh-mcp

Two Wazuh MCP Server containers attached to the Wazuh stack in `C:\Users\schug\src\docker\wazuh` (Compose project `single-node`):

- `wazuh-mcp`: for Claude Code. Bound to 127.0.0.1:3000, bearer-token auth, and active response through the `mcp-write` API user.
- `wazuh-mcp-ha`: for Home Assistant's MCP client, which can't send a bearer token. Authless and read-only, published on the desktop's LAN address port 3001, with Windows Firewall and UniFi rules limiting it to the HA host.

Setup order (PowerShell, in this folder):

1. `.\create-mcp-user.ps1` - creates the read-only `mcp-service` API user in Wazuh (needs the stack running); `.env` holds its credentials
2. `.\create-mcp-write-user.ps1` - creates the `mcp-write` user with active response and writes `.env.write`, which only `wazuh-mcp` loads (set `WAZUH_API_ADMIN_PASSWORD` in the shell first)
3. `docker compose up -d`
4. `curl http://127.0.0.1:3000/health` and `curl http://127.0.0.1:3000/ready`
5. `.\mint-token.ps1` - mints a 1-year JWT and prints the `claude mcp add` command

Notes

- Port 3000 (Claude Code) is bound to 127.0.0.1 only. Port 3001 (Home Assistant) is on the LAN address, so keep its firewall scoping in place; it never loads `.env.write`, so it can't run active response.
- The container joins the external network `single-node_default`; if the Wazuh stack ever moves to a project with a different name, update `networks.wazuh.name` in compose.yml.
- Active response is on for `wazuh-mcp` via `.env.write` (`wazuh:write` scope plus the `response` toolset). After changing scopes, re-run mint-token.ps1; an existing JWT keeps the scope it was minted with. `WAZUH_PROTECTED_IPS` keeps the home LAN and the tailnet from being blocked.
- `.env`, `.env.write` and `claude-code-token.txt` hold secrets; do not commit them anywhere.
