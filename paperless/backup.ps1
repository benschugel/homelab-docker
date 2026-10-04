# Nightly Paperless-ngx export. Mirrors every document plus the database manifest into .\export
# (next to this script), then mirrors that folder to a second drive.
#
# Sensitive manifest fields (such as a mail account password) are encrypted with a passphrase that is
# stored DPAPI-protected in export-passphrase.dpapi.xml next to this script. Create it once with:
#   Read-Host -AsSecureString 'Export passphrase' | Export-Clixml .\export-passphrase.dpapi.xml
# DPAPI ties the file to the Windows account that created it, so schedule this script as that account.
#
# Restore with: docker compose exec -T webserver document_importer ../export --passphrase <passphrase>
#
# All paths are relative to this script's folder, so the stack can live anywhere.

$stack  = $PSScriptRoot
$log    = Join-Path $stack 'backup.log'
$oldLog = Join-Path $stack 'backup.old.log'
$ppFile = Join-Path $stack 'export-passphrase.dpapi.xml'
$src    = Join-Path $stack 'export'
$dst    = 'D:\paperless backups\export'   # second-drive mirror
$docker = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'

function Stamp { Get-Date -Format 'yyyy-MM-dd HH:mm:ss' }

if ((Test-Path $log) -and ((Get-Item $log).Length -gt 2MB)) { Move-Item $log $oldLog -Force }
Add-Content $log "[$(Stamp)] export starting"

if (-not (Test-Path $ppFile)) { Add-Content $log "[$(Stamp)] ABORTED: passphrase file missing, nothing exported"; exit 1 }
$sec  = Import-Clixml $ppFile
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
$pp   = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

& $docker compose -f (Join-Path $stack 'docker-compose.yml') --project-directory $stack exec -T webserver document_exporter ../export -d --no-progress-bar --passphrase $pp 2>&1 | Out-File -Append -Encoding utf8 $log
$exportCode = $LASTEXITCODE
Add-Content $log "[$(Stamp)] export finished, exit code $exportCode"
if ($exportCode -ne 0) { Add-Content $log "[$(Stamp)] copy to D skipped because the export failed (previous copy kept)"; exit $exportCode }

if (-not (Test-Path (Split-Path $dst -Qualifier))) { Add-Content $log "[$(Stamp)] copy skipped: $(Split-Path $dst -Qualifier) not available"; exit 2 }
New-Item -ItemType Directory -Force -Path $dst | Out-Null
& robocopy $src $dst /MIR /R:2 /W:5 /NP /NFL /NDL /NJH /NJS | Out-Null
$rc = $LASTEXITCODE
$count = (Get-ChildItem $dst -Recurse -File | Measure-Object).Count
if ($rc -lt 8) { Add-Content $log "[$(Stamp)] copy to $dst ok (robocopy code $rc, $count files)"; exit 0 } else { Add-Content $log "[$(Stamp)] copy to $dst FAILED (robocopy code $rc)"; exit $rc }
