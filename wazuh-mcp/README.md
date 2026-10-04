# wazuh-mcp

Wazuh MCP Server container for Claude Code, attached to the Wazuh single-node stack in `C:\docker\wazuh\single-node`.

Setup order (PowerShell, in this folder):

1. `.\create-mcp-user.ps1` - creates the read-only `mcp-service` API user in Wazuh (needs the stack running)
2. `docker compose up -d`
3. `curl http://127.0.0.1:3000/health` and `curl http://127.0.0.1:3000/ready`
4. `.\mint-token.ps1` - mints a 1-year JWT and prints the `claude mcp add` command

Notes

- Port 3000 is bound to 127.0.0.1 only. Nothing on the LAN can reach it.
- The container joins the external network `single-node_default`; if the Wazuh stack ever moves to a project with a different name, update `networks.wazuh.name` in compose.yml.
- API key is read-only. To allow active response: set `MCP_API_KEY_SCOPES="wazuh:read wazuh:write"`, add `response` to `WAZUH_TOOLSETS`, `docker compose up -d`, then re-run mint-token.ps1 (the old JWT keeps read-only scope).
- `.env` and `claude-code-token.txt` hold secrets; do not commit them anywhere.
