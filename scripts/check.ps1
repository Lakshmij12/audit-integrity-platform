<#
.SYNOPSIS
Runs the quality gates (Ruff, mypy, pytest with coverage) and the tamper demo in a Python 3.14
container. Only Docker is required; the checkout is mounted read-only.

.EXAMPLE
.\scripts\check.ps1
#>
$ErrorActionPreference = "Continue"   # docker progress goes to stderr; the exit code is checked
$Root = Split-Path -Parent $PSScriptRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Docker is not installed. Install Docker Desktop and run this script again." -ForegroundColor Red
    exit 1
}
# The pip cache volume makes later runs faster; it holds only downloaded packages.
& docker run --rm -v "${Root}:/src:ro" -v aip-pip-cache:/root/.cache/pip python:3.14-slim sh /src/scripts/checks.sh
exit $LASTEXITCODE
