<#
.SYNOPSIS
Builds and starts the Audit Integrity Platform in Docker: API, test UI and an optional SQLite browser.

.DESCRIPTION
Only Docker Desktop is required; everything else runs in containers. On the first run the script
creates three API keys (writer, auditor, admin) in keys/api-keys.txt, their SHA-256 entries in
keys/aip.env, and an Ed25519 signing key in the aip-keys volume. Later runs reuse them. keys/ is
git-ignored.

.EXAMPLE
.\scripts\start.ps1             # build and start the API (8000) and the test UI (8080)
.\scripts\start.ps1 -DbAdmin    # also start the SQLite browser (8082)
.\scripts\start.ps1 -Reset      # delete all audit data first, then start (keys are kept)
.\scripts\start.ps1 -Stop       # stop and remove the containers (data and keys are kept)
.\scripts\start.ps1 -ShowKeys   # print the API keys at the end
#>
[CmdletBinding()]
param(
    [switch]$DbAdmin,
    [switch]$Reset,
    [switch]$Stop,
    [switch]$ShowKeys
)

# Docker writes progress to stderr; with "Stop", Windows PowerShell 5.1 turns that into a terminating
# error. Every docker call checks $LASTEXITCODE instead.
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Image = "audit-integrity-platform"
$ContainerNames = @("aip", "aip-ui", "aip-sqlite-web")
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Step([string]$Text) { Write-Host "==> $Text" -ForegroundColor Cyan }
function Fail([string]$Text) { Write-Host "ERROR: $Text" -ForegroundColor Red; exit 1 }

# Runs docker and stops the script if it fails. Output is returned, not printed.
function Invoke-Docker {
    $output = & docker @args
    if ($LASTEXITCODE -ne 0) { Fail "docker $($args -join ' ') failed (exit code $LASTEXITCODE)" }
    $output
}

# True when the command exits 0. Runs through cmd so stderr never becomes a PowerShell error.
function Test-Quiet([string]$Command) {
    cmd /c "$Command >nul 2>&1"
    $LASTEXITCODE -eq 0
}

# --- Docker -------------------------------------------------------------------------------------
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Fail "Docker is not installed. Install Docker Desktop from https://www.docker.com/products/docker-desktop/ and run this script again."
}
if (-not (Test-Quiet "docker info")) {
    $desktop = @(
        "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
        "$env:LOCALAPPDATA\Programs\DockerDesktop\Docker Desktop.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $desktop) { Fail "The Docker engine is not running. Start Docker Desktop and run this script again." }
    Step "Starting Docker Desktop (this can take a minute)"
    Start-Process $desktop
    $deadline = (Get-Date).AddMinutes(3)
    while (-not (Test-Quiet "docker info")) {
        if ((Get-Date) -gt $deadline) { Fail "Docker Desktop did not start within 3 minutes. Open it, accept any prompts, and run this script again." }
        Start-Sleep -Seconds 3
    }
}
if (-not (Test-Quiet "docker compose version")) { Fail "Docker Compose v2 is missing. Update Docker Desktop." }

# Containers with these names that docker compose did not create (an older manual setup) would
# block `compose up`. Remove them; their data lives in the named volumes and is kept.
function Remove-LegacyContainers {
    $managed = @(Invoke-Docker ps -a --filter "label=com.docker.compose.project=aip" --format "{{.Names}}")
    foreach ($name in @(Invoke-Docker ps -a --format "{{.Names}}")) {
        if ($ContainerNames -contains $name -and $managed -notcontains $name) {
            Step "Removing container '$name' from the earlier manual setup (data is kept)"
            Invoke-Docker rm -f $name | Out-Null
        }
    }
}

if ($Stop) {
    Step "Stopping the stack (data and keys are kept)"
    Invoke-Docker compose --profile dbadmin down | Out-Null
    Remove-LegacyContainers
    Write-Host "Stopped. Start again with .\scripts\start.ps1"
    exit 0
}

if ($Reset) {
    Step "Deleting all audit data (volumes aip-data and aip-archives; keys are kept)"
    Invoke-Docker compose --profile dbadmin down | Out-Null
    Remove-LegacyContainers
    $volumes = @(Invoke-Docker volume ls -q)
    foreach ($volume in "aip-data", "aip-archives") {
        if ($volumes -contains $volume) { Invoke-Docker volume rm $volume | Out-Null }
    }
}

# --- Image --------------------------------------------------------------------------------------
Step "Building the API image"
& docker compose build aip
if ($LASTEXITCODE -ne 0) { Fail "The image build failed; see the output above." }

# --- Keys ---------------------------------------------------------------------------------------
New-Item -ItemType Directory -Force (Join-Path $Root "keys") | Out-Null
$EnvFile = Join-Path $Root "keys\aip.env"
$KeyFile = Join-Path $Root "keys\api-keys.txt"
$NewKeys = $false

if (-not (Test-Path $EnvFile)) {
    Step "Creating API keys for writer, auditor and admin"
    $lines = @(
        "# API keys for the local aip stack. Keep them private (keys/ is git-ignored).",
        "# Paste each key into the matching box at http://127.0.0.1:8080"
    )
    $entries = @()
    foreach ($role in "writer", "auditor", "admin") {
        $out = Invoke-Docker run --rm $Image python -m aip.cli new-api-key --role $role
        $key = ($out | Select-String '^api key \(shown once\): (\S+)').Matches[0].Groups[1].Value
        $entry = ($out | Select-String '^AIP_API_KEYS entry:\s+(\S+)').Matches[0].Groups[1].Value
        $lines += "$role key: $key"
        $entries += $entry
    }
    [IO.File]::WriteAllText($KeyFile, (($lines -join "`n") + "`n"), $Utf8NoBom)
    [IO.File]::WriteAllText($EnvFile, "AIP_API_KEYS=$($entries -join ',')`nAIP_SIGNING_KEY_PATH=keys/signing.pem`n", $Utf8NoBom)
    $NewKeys = $true
}

Remove-LegacyContainers
& docker compose run --rm --no-deps aip test -f keys/signing.pem
if ($LASTEXITCODE -ne 0) {
    Step "Creating the Ed25519 signing key (volume aip-keys)"
    $out = Invoke-Docker compose run --rm --no-deps aip python -m aip.cli new-signing-key --out keys/signing.pem
    $public = ($out | Select-String 'public key \(hex\):\s+(\S+)').Matches[0].Groups[1].Value
    [IO.File]::AppendAllText($KeyFile, "`nsigning public key (hex): $public`n", $Utf8NoBom)
}

# --- Start --------------------------------------------------------------------------------------
$profileArgs = @()
if ($DbAdmin) { $profileArgs = @("--profile", "dbadmin") }
Step "Starting the containers"
& docker compose @profileArgs up -d
if ($LASTEXITCODE -ne 0) {
    & docker logs --tail 30 aip
    Fail "The stack did not start. If the log says 'unexpected schema', the database was edited by hand: run .\scripts\start.ps1 -Reset"
}

$health = ""
for ($i = 0; $i -lt 60; $i++) {
    $health = (& docker inspect -f "{{.State.Health.Status}}" aip)
    if ($health -eq "healthy") { break }
    Start-Sleep -Seconds 1
}
if ($health -ne "healthy") {
    & docker logs --tail 30 aip
    Fail "The API is not healthy ($health). If the log says 'unexpected schema', run .\scripts\start.ps1 -Reset"
}

# --- Summary ------------------------------------------------------------------------------------
Write-Host ""
Write-Host "Audit Integrity Platform is running" -ForegroundColor Green
Write-Host "  Test UI         http://127.0.0.1:8080"
Write-Host "  API docs        http://127.0.0.1:8000/docs"
if ($DbAdmin) { Write-Host "  SQLite browser  http://127.0.0.1:8082" }
Write-Host ""
if ($NewKeys -or $ShowKeys) {
    Write-Host "API keys (also saved in keys\api-keys.txt):" -ForegroundColor Yellow
    Get-Content $KeyFile | Where-Object { $_ -match ' key: ' } | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Host "API keys: keys\api-keys.txt (run with -ShowKeys to print them)"
}
Write-Host ""
Write-Host "Paste the keys into the boxes at the top of the test UI, then try Write > Load 12 sample events"
Write-Host "and Verify > Verify now. Stop with .\scripts\start.ps1 -Stop"
