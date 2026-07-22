param(
    [string]$ProjectRoot = "C:\Users\LeighMC\Documents\Codex\2026-07-11\SBP_LEX_DUAL_V6_DESKTOP_V1",
    [string]$InstallRoot = "$env:LOCALAPPDATA\SBP\ExternalWindowsAgentV1"
)

$ErrorActionPreference = "Stop"
$SourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Get-Command py -ErrorAction SilentlyContinue
if (-not $Python) {
    throw "Python launcher 'py' was not found. Install Python or make the launcher available first."
}

New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
$PackageRoot = Join-Path $InstallRoot "package"
if (Test-Path $PackageRoot) {
    Remove-Item $PackageRoot -Recurse -Force
}
Copy-Item $SourceRoot $PackageRoot -Recurse -Force

$Venv = Join-Path $InstallRoot ".venv"
& py -3 -m venv $Venv
$VenvPython = Join-Path $Venv "Scripts\python.exe"

$DataDir = Join-Path $InstallRoot "data"
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
$ConfigPath = Join-Path $InstallRoot "config.json"
@{
    data_dir = $DataDir
    project_root = $ProjectRoot
    python_executable = $VenvPython
} | ConvertTo-Json | Set-Content -Path $ConfigPath -Encoding UTF8

$Launcher = Join-Path $InstallRoot "SBP-External-Agent.cmd"
@"
@echo off
set SBP_EXTERNAL_AGENT_CONFIG=$ConfigPath
set PYTHONPATH=$PackageRoot\src
"$VenvPython" -m sbp_external_agent.app %*
"@ | Set-Content -Path $Launcher -Encoding ASCII

Write-Host "Installed: $InstallRoot"
Write-Host "Launcher:  $Launcher"
Write-Host "Status:    `"$Launcher`" status"
