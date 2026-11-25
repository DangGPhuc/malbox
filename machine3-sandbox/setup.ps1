<#
.SYNOPSIS
    One-command idempotent setup and environment readiness checker for MalBox Machine 3 (Windows 11 Sandbox).
.DESCRIPTION
    Default mode ensures directories, Python .venv, dependencies, and MCP config exist (reusing install.ps1
    when missing or when -Force / -CloneGitTools is passed), then runs readiness.py and saves setup_report.json.
    Pass -CheckOnly to perform a strictly offline, non-modifying readiness check.
#>
param(
    [switch]$CheckOnly,
    [switch]$CloneGitTools,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$SandboxDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $SandboxDir

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $global:LASTEXITCODE = 0
        & $Executable @Arguments
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevPref
    }
}

$Arch = $env:PROCESSOR_ARCHITECTURE
if (-not $Arch) { $Arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() }

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " MalBox Machine 3 (Windows 11 Sandbox) - Setup & Readiness" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "OS / Arch : $([System.Environment]::OSVersion.VersionString) / $Arch"
Write-Host "PowerShell: $($PSVersionTable.PSVersion)"

$VenvPython = Join-Path $SandboxDir ".venv\Scripts\python.exe"
$McpTarget = Join-Path $SandboxDir "mcp\config.json"

if ($CheckOnly) {
    Write-Host "Mode      : CHECK-ONLY (offline, non-modifying)" -ForegroundColor Yellow
    $PyExec = $null
    $PyPrefix = @()
    if (Test-Path $VenvPython) {
        $PyExec = $VenvPython
    } else {
        $SysPy = Get-Command python -ErrorAction SilentlyContinue
        if (-not $SysPy) { $SysPy = Get-Command py -ErrorAction SilentlyContinue }
        if ($SysPy) {
            $PyExec = $SysPy.Source
            if ($SysPy.Name -eq "py.exe" -or $SysPy.Name -eq "py") {
                $PyPrefix = @("-3")
            }
        }
    }

    if (-not $PyExec) {
        Write-Host "[ERROR] Neither .venv nor system Python was found." -ForegroundColor Red
        exit 1
    }

    $rc = Invoke-Native $PyExec ($PyPrefix + @((Join-Path $SandboxDir "readiness.py"), "--mode", "check-only"))
    exit $rc
}

Write-Host "Mode      : SETUP (idempotent)"

$NeedsInstall = $false
if ($Force -or $CloneGitTools) {
    $NeedsInstall = $true
} elseif (-not (Test-Path $VenvPython)) {
    $NeedsInstall = $true
} elseif (-not (Test-Path $McpTarget)) {
    $NeedsInstall = $true
} else {
    $importRc = Invoke-Native $VenvPython @("-c", "import flask, requests, psutil, pefile, yara, Evtx, mcp")
    if ($importRc -ne 0) {
        $NeedsInstall = $true
    }
}

# Ensure base folders exist without altering .dirty_state or existing evidence
foreach ($d in @("workspace", "evidence", "tools", "scripts\yara_rules")) {
    $full = Join-Path $SandboxDir $d
    if (-not (Test-Path $full)) {
        New-Item -ItemType Directory -Path $full -Force | Out-Null
    }
}

if ($NeedsInstall) {
    Write-Host "[SETUP] Running install.ps1..." -ForegroundColor Cyan
    $InstallScript = Join-Path $SandboxDir "install.ps1"
    if ($CloneGitTools) {
        & $InstallScript -CloneGitTools
    } else {
        & $InstallScript
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] install.ps1 exited with code $LASTEXITCODE." -ForegroundColor Red
        exit $LASTEXITCODE
    }
} else {
    Write-Host "[OK] Existing .venv, core Python packages, and mcp\config.json detected (skipping reinstall)." -ForegroundColor Green
}

$rc = Invoke-Native $VenvPython @((Join-Path $SandboxDir "readiness.py"), "--mode", "setup")
exit $rc
