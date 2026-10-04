# Exchanges the MCP_API_KEY for a bearer JWT (lifetime = TOKEN_LIFETIME_HOURS in .env)
# and prints the command that registers the server in Claude Code.
# Run from PowerShell after `docker compose up -d`:  .\mint-token.ps1
$ErrorActionPreference = "Stop"
$key  = (Get-Content "$PSScriptRoot\.env" | Where-Object { $_ -like "MCP_API_KEY=*" }) -replace "^MCP_API_KEY=", ""
$bodyFile = Join-Path $env:TEMP "wazuh-mcp-token.json"
@{ api_key = $key } | ConvertTo-Json -Compress | Set-Content -Path $bodyFile -Encoding ASCII -NoNewline
$r = curl.exe -s -X POST "http://127.0.0.1:3000/auth/token" -H "Content-Type: application/json" -d "@$bodyFile" | ConvertFrom-Json
Remove-Item $bodyFile -ErrorAction SilentlyContinue
if (-not $r.access_token) { throw "Token request failed: $($r | ConvertTo-Json -Compress)" }
$jwt = $r.access_token
Set-Content -Path "$PSScriptRoot\claude-code-token.txt" -Value $jwt
Write-Host "JWT saved to claude-code-token.txt (expires in $([math]::Round($r.expires_in/3600)) h)"
Write-Host ""
Write-Host "Register in Claude Code (user scope, so it's available in every project):"
Write-Host ""
Write-Host "claude mcp add --transport http --scope user wazuh http://127.0.0.1:3000/mcp --header `"Authorization: Bearer $jwt`""
