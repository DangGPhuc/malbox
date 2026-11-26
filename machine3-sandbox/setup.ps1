<#
.SYNOPSIS
    One-command idempotent setup and environment readiness checker for MalBox Machine 3 (Windows 11 Sandbox).
.DESCRIPTION
    Default mode ensures directories, 64-bit Python 3.10+ .venv, dependencies, and MCP config exist
    (reusing install.ps1 when missing or when -Force / -CloneGitTools is passed), then runs readiness.py
    and saves setup_report.json. Pass -CheckOnly for a strictly offline, non-modifying readiness check.
    Exit codes:
      0 - Mandatory local checks passed (LOCAL_READINESS is READY or LIMITED)
      1 - LOCAL_READINESS is NOT_READY, prerequisite missing, or install.ps1 failed
      2 - Invalid command-line arguments
#>
param(
    [switch]$CheckOnly,
    [switch]$CloneGitTools,
    [switch]$Force,
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$UnexpectedArgs
)

$ErrorActionPreference = "Stop"
$SandboxDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $SandboxDir

if ($Help) {
    Write-Host "Usage: .\setup.ps1 [-CheckOnly] [-CloneGitTools] [-Force] [-Help]"
    Write-Host "  -CheckOnly      Offline, non-modifying readiness check (saves setup_report.json)."
    Write-Host "  -CloneGitTools  Clone capa-rules, volatility3, and GhidraMCP via install.ps1 (while online)."
    Write-Host "  -Force          Re-run install.ps1 even if environment appears configured."
    exit 0
}

if ($UnexpectedArgs -and $UnexpectedArgs.Count -gt 0) {
    Write-Host "[ERROR] Unknown argument(s): $($UnexpectedArgs -join ' ')" -ForegroundColor Red
    Write-Host "Usage: .\setup.ps1 [-CheckOnly] [-CloneGitTools] [-Force] [-Help]"
    exit 2
}

function Invoke-Native {
    <#
    .SYNOPSIS
        Execute a native command while streaming its terminal output directly to the host
        and returning ONLY a single integer exit code (never mixed with stdout).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $false)][string[]]$Arguments = @()
    )
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    [int]$exitCode = 1
    try {
        $global:LASTEXITCODE = 0
        if ($Arguments -and $Arguments.Count -gt 0) {
            & $Executable @Arguments | Out-Host
        } else {
            & $Executable | Out-Host
        }
        if ($null -eq $LASTEXITCODE) {
            $exitCode = 0
        } else {
            $exitCode = [int]$LASTEXITCODE
        }
    } catch {
        Write-Host "[ERROR] Failed executing ${Executable}: $_" -ForegroundColor Red
        $exitCode = 1
    } finally {
        $ErrorActionPreference = $prevPref
    }
    return $exitCode
}

function Find-RunnablePython {
    $candidates = @()
    $pyExe = Get-Command python -ErrorAction SilentlyContinue
    if ($pyExe -and $pyExe.Source -notlike "*\WindowsApps\python*.exe") {
        $candidates += @{ Source = $pyExe.Source; Prefix = @() }
    }
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        $candidates += @{ Source = $pyLauncher.Source; Prefix = @("-3") }
    }
    if ($pyExe -and $pyExe.Source -like "*\WindowsApps\python*.exe") {
        $candidates += @{ Source = $pyExe.Source; Prefix = @() }
    }

    foreach ($cand in $candidates) {
        $prevPref = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $global:LASTEXITCODE = 0
            $probeArgs = $cand.Prefix + @("-c", "import sys; print(sys.executable)")
            $null = & $cand.Source @probeArgs 2>$null
            if ($LASTEXITCODE -eq 0) {
                return $cand
            }
        } catch {
            # Ignore non-functional Store alias stubs
        } finally {
            $ErrorActionPreference = $prevPref
        }
    }
    return $null
}

$Arch = $env:PROCESSOR_ARCHITECTURE
if (-not $Arch) { $Arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() }

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " MalBox Machine 3 (Windows 10/11 Sandbox) - Setup & Readiness" -ForegroundColor Cyan
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
        $foundPy = Find-RunnablePython
        if ($foundPy) {
            $PyExec = $foundPy.Source
            $PyPrefix = $foundPy.Prefix
        }
    }

    if (-not $PyExec) {
        Write-Host "[ERROR] Neither .venv nor a runnable system Python was found." -ForegroundColor Red
        exit 1
    }

    [int]$rc = Invoke-Native -Executable $PyExec -Arguments ($PyPrefix + @((Join-Path $SandboxDir "readiness.py"), "--mode", "check-only"))
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
    [int]$envCheckRc = Invoke-Native -Executable $VenvPython -Arguments @(
        "-c",
        "import sys, struct, flask, requests, psutil, pefile, yara, Evtx, mcp; sys.exit(0 if (sys.version_info >= (3, 10) and struct.calcsize('P') * 8 == 64) else 1)"
    )
    if ($envCheckRc -ne 0) {
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
    $global:LASTEXITCODE = 0
    if ($CloneGitTools) {
        & $InstallScript -CloneGitTools
    } else {
        & $InstallScript
    }
    [int]$installRc = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    if ($installRc -ne 0) {
        Write-Host "[ERROR] install.ps1 exited with code $installRc." -ForegroundColor Red
        exit $installRc
    }
} else {
    Write-Host "[OK] Existing 64-bit Python 3.10+ .venv, core packages, and mcp\config.json detected (skipping reinstall)." -ForegroundColor Green
}

if (-not (Test-Path $VenvPython)) {
    Write-Host "[ERROR] Expected virtual environment Python missing at $VenvPython." -ForegroundColor Red
    exit 1
}

[int]$rc = Invoke-Native -Executable $VenvPython -Arguments @((Join-Path $SandboxDir "readiness.py"), "--mode", "setup")
exit $rc
