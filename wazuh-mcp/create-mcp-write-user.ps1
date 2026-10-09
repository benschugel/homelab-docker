# Creates a Wazuh API user for the Claude Code MCP instance (wazuh-mcp) with
# read access plus active response, and generates .env.write (keep it out of git)
# holding that user's credentials and the write-mode MCP settings.
# The HA instance (wazuh-mcp-ha) never loads .env.write, so it stays read-only.
# Run from C:\docker\wazuh-mcp while the Wazuh stack is up:  .\create-mcp-write-user.ps1
# Safe to re-run: reuses the password in .env.write and skips anything that already exists.
$ErrorActionPreference = "Stop"
$api     = "https://localhost:55000"
$admin   = "wazuh-wui"
$adminPw = $env:WAZUH_API_ADMIN_PASSWORD
if (-not $adminPw) { throw "Set WAZUH_API_ADMIN_PASSWORD in this shell before running (the wazuh-wui API password)." }
$newUser = "mcp-write"
$arName  = "mcp-active-response"
$envFile = Join-Path $PSScriptRoot ".env.write"

# --- 1. Generate .env.write once (crypto RNG; meets Wazuh's upper/lower/digit/symbol rule) ---
if (-not (Test-Path $envFile)) {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    function Get-RandIndex([int]$max) { $b = New-Object byte[] 4; $rng.GetBytes($b); [int]([BitConverter]::ToUInt32($b, 0) % $max) }
    $sets  = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '@*-+.')
    $all   = -join $sets
    $chars = @($sets | ForEach-Object { $_[(Get-RandIndex $_.Length)] })
    $chars += 1..28 | ForEach-Object { $all[(Get-RandIndex $all.Length)] }
    $pw = -join ($chars | Sort-Object { Get-RandIndex 1000000 })

    @(
        "# Overrides for the Claude Code instance (wazuh-mcp) only. Loaded after .env."
        "# Created by create-mcp-write-user.ps1. Do not commit."
        "WAZUH_USER=$newUser"
        "WAZUH_PASS=$pw"
        'MCP_API_KEY_SCOPES="wazuh:read wazuh:write"'
        "WAZUH_TOOLSETS=alerts,agents,vulnerabilities,analysis,compliance,system,response"
        "# Home LAN plus the tailnet (laptop fails over to Ben-PC's Tailscale address)"
        "WAZUH_PROTECTED_IPS=192.168.0.0/16,100.64.0.0/10"
    ) | Set-Content -Path $envFile -Encoding ASCII
    Write-Host "Wrote $envFile"
} else {
    Write-Host "$envFile already exists; reusing its password."
}
$pw = (Get-Content $envFile | Where-Object { $_ -like "WAZUH_PASS=*" }) -replace "^WAZUH_PASS=", ""

# --- 2. Authenticate as admin ---
$tok = (curl.exe -sk -u "${admin}:${adminPw}" -X POST "$api/security/user/authenticate?raw=true")
if (-not $tok -or $tok -like "*error*") { throw "Could not authenticate to the Wazuh API: $tok" }
$h = @("-H", "Authorization: Bearer $tok", "-H", "Content-Type: application/json")

function Invoke-WzBody([string]$method, [string]$path, $body) {
    $f = Join-Path $env:TEMP ("wz-" + [guid]::NewGuid().ToString("N") + ".json")
    $body | ConvertTo-Json -Depth 6 -Compress | Set-Content -Path $f -Encoding ASCII -NoNewline
    try { curl.exe -sk @h -X $method "$api$path" -d "@$f" | ConvertFrom-Json }
    finally { Remove-Item $f -ErrorAction SilentlyContinue }
}

# --- 3. Create the user, or sync its password to .env.write if it already exists ---
$existing = (curl.exe -sk @h "$api/security/users?search=$newUser" | ConvertFrom-Json).data.affected_items | Where-Object { $_.username -eq $newUser }
if ($existing) {
    $uid = $existing.id
    $r = Invoke-WzBody "PUT" "/security/users/$uid" @{ password = $pw }
    if ($r.error -ne 0) { throw "Password sync failed: $($r | ConvertTo-Json -Compress -Depth 6)" }
    Write-Host "User $newUser already existed (id $uid); password synced to .env.write."
} else {
    $r = Invoke-WzBody "POST" "/security/users" @{ username = $newUser; password = $pw }
    if ($r.error -ne 0) { throw "Create user failed: $($r | ConvertTo-Json -Compress -Depth 6)" }
    $uid = $r.data.affected_items[0].id
    Write-Host "Created user $newUser (id $uid)"
}

# --- 4. Policy: active response commands and agent restarts, on all agents ---
$pol = (curl.exe -sk @h "$api/security/policies?limit=500" | ConvertFrom-Json).data.affected_items | Where-Object { $_.name -eq $arName }
if ($pol) {
    $pid2 = $pol.id
    Write-Host "Policy $arName already exists (id $pid2)"
} else {
    $r = Invoke-WzBody "POST" "/security/policies" @{
        name   = $arName
        policy = @{ actions = @("active-response:command", "agent:restart"); resources = @("agent:id:*"); effect = "allow" }
    }
    if ($r.error -ne 0) { throw "Create policy failed: $($r | ConvertTo-Json -Compress -Depth 6)" }
    $pid2 = $r.data.affected_items[0].id
    Write-Host "Created policy $arName (id $pid2)"
}

# --- 5. Role wrapping that policy ---
$roles = (curl.exe -sk @h "$api/security/roles?limit=500" | ConvertFrom-Json).data.affected_items
$ar = $roles | Where-Object { $_.name -eq $arName }
if ($ar) {
    $arId = $ar.id
    Write-Host "Role $arName already exists (id $arId)"
} else {
    $r = Invoke-WzBody "POST" "/security/roles" @{ name = $arName }
    if ($r.error -ne 0) { throw "Create role failed: $($r | ConvertTo-Json -Compress -Depth 6)" }
    $arId = $r.data.affected_items[0].id
    Write-Host "Created role $arName (id $arId)"
}
$r = curl.exe -sk @h -X POST "$api/security/roles/$arId/policies?policy_ids=$pid2" | ConvertFrom-Json
Write-Host "Linked policy to role: error=$($r.error) $($r.message)"

# --- 6. Give the user readonly + active response ---
$roId = ($roles | Where-Object { $_.name -eq "readonly" }).id
$r = curl.exe -sk @h -X POST "$api/security/users/$uid/roles?role_ids=$roId,$arId" | ConvertFrom-Json
Write-Host "Assigned roles readonly (id $roId) and $arName (id $arId): error=$($r.error) $($r.message)"

# --- 7. Prove the new user can log in and read ---
$t2 = (curl.exe -sk -u "${newUser}:${pw}" -X POST "$api/security/user/authenticate?raw=true")
if (-not $t2 -or $t2 -like "*error*") { throw "Login as $newUser failed: $t2" }
$agents = curl.exe -sk -H "Authorization: Bearer $t2" "$api/agents?select=id,name,status" | ConvertFrom-Json
Write-Host "Login as $newUser OK. Agents visible:"
$agents.data.affected_items | Format-Table id, name, status
