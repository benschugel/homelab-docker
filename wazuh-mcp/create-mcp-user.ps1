# Creates a dedicated read-only Wazuh API user for the MCP server.
# Run once from PowerShell while the Wazuh stack is up:  .\create-mcp-user.ps1
$ErrorActionPreference = "Stop"
$api      = "https://localhost:55000"
$admin    = "wazuh-wui"
$adminPw  = $env:WAZUH_API_ADMIN_PASSWORD
if (-not $adminPw) { throw "Set WAZUH_API_ADMIN_PASSWORD in this shell before running (the wazuh-wui API password)." }
$newUser  = "mcp-service"
$newPw    = (Get-Content "$PSScriptRoot\.env" | Where-Object { $_ -like "WAZUH_PASS=*" }) -replace "^WAZUH_PASS=", ""

$tok = (curl.exe -sk -u "${admin}:${adminPw}" -X POST "$api/security/user/authenticate?raw=true")
if (-not $tok -or $tok -like "*error*") { throw "Could not authenticate to the Wazuh API: $tok" }
$h = @("-H", "Authorization: Bearer $tok", "-H", "Content-Type: application/json")

$existing = (curl.exe -sk @h "$api/security/users?search=$newUser" | ConvertFrom-Json).data.affected_items | Where-Object { $_.username -eq $newUser }
if ($existing) {
    $uid = $existing.id
    Write-Host "User $newUser already exists (id $uid); leaving password unchanged."
} else {
    $bodyFile = Join-Path $env:TEMP "wazuh-mcp-user.json"
    @{ username = $newUser; password = $newPw } | ConvertTo-Json -Compress | Set-Content -Path $bodyFile -Encoding ASCII -NoNewline
    $r = curl.exe -sk @h -X POST "$api/security/users" -d "@$bodyFile" | ConvertFrom-Json
    Remove-Item $bodyFile -ErrorAction SilentlyContinue
    if ($r.error -ne 0) { throw "Create user failed: $($r | ConvertTo-Json -Compress)" }
    $uid = $r.data.affected_items[0].id
    Write-Host "Created user $newUser (id $uid)"
}

$roles = (curl.exe -sk @h "$api/security/roles" | ConvertFrom-Json).data.affected_items
$rid = ($roles | Where-Object { $_.name -eq "readonly" }).id
$r = curl.exe -sk @h -X POST "$api/security/users/$uid/roles?role_ids=$rid" | ConvertFrom-Json
Write-Host "Assigned role readonly (id $rid): error=$($r.error) $($r.message)"

# Prove the new user can log in and read
$t2 = (curl.exe -sk -u "${newUser}:${newPw}" -X POST "$api/security/user/authenticate?raw=true")
$agents = curl.exe -sk -H "Authorization: Bearer $t2" "$api/agents?select=id,name,status" | ConvertFrom-Json
Write-Host "Login as $newUser OK. Agents visible:"
$agents.data.affected_items | Format-Table id, name, status
