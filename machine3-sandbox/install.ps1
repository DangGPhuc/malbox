<#
.SYNOPSIS
    Prepares MalBox Machine 3 Windows 11 Sandbox Python environment, folders, MCP config, and checks tools.
.DESCRIPTION
    Run this script BEFORE isolating the VM from the Internet and BEFORE taking the CLEAN snapshot.
    Pass -CloneGitTools to git clone open-source repositories (capa-rules, volatility3, GhidraMCP) into .\tools\.
    Compatible with both Windows PowerShell 5.1 and PowerShell 7+.
#>
param(
    [switch]$CloneGitTools
)

$ErrorActionPreference = "Stop"
$SandboxDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $SandboxDir

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

function Read-Utf8Text {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )
    return [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $global:LASTEXITCODE = 0
        & $Executable @Arguments
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevPref
    }
    if ($exitCode -ne 0) {
        throw "$Description failed with exit code $exitCode."
    }
}

function Find-FirstExisting {
    param([string[]]$Candidates)
    foreach ($c in $Candidates) {
        if ($c -and (Test-Path $c)) {
            return $c
        }
    }
    return $null
}

Write-Host "[INSTALL] Initializing MalBox Machine 3 Sandbox in $SandboxDir..." -ForegroundColor Cyan

# 1. Create required folders (do NOT pre-create tools\volatility3\symbols before git clone volatility3)
$dirs = @(
    "workspace",
    "evidence",
    "tools",
    "tools\floss",
    "tools\capa",
    "tools\yara",
    "tools\sysinternals",
    "tools\winpmem",
    "scripts\yara_rules"
)
foreach ($d in $dirs) {
    $full = Join-Path $SandboxDir $d
    if (-not (Test-Path $full)) {
        New-Item -ItemType Directory -Path $full -Force | Out-Null
    }
}

# 2. Locate Python and create virtual environment + install required Python packages
$PythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    $PythonCmd = Get-Command py -ErrorAction SilentlyContinue
}
if (-not $PythonCmd) {
    Write-Host "[ERROR] Python 3.11+ not found in PATH. Install Python first." -ForegroundColor Red
    exit 1
}

$VenvDir = Join-Path $SandboxDir ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"

try {
    if (-not (Test-Path $VenvPython)) {
        Write-Host "[INSTALL] Creating Python virtual environment..."
        if ($PythonCmd.Name -eq "py.exe" -or $PythonCmd.Name -eq "py") {
            Invoke-Checked $PythonCmd.Source @("-3", "-m", "venv", $VenvDir) "Create virtual environment"
        } else {
            Invoke-Checked $PythonCmd.Source @("-m", "venv", $VenvDir) "Create virtual environment"
        }
    }

    if (-not (Test-Path $VenvPython)) {
        throw "Virtual environment Python not found at $VenvPython"
    }

    Write-Host "[INSTALL] Upgrading pip and installing requirements.txt..."
    Invoke-Checked $VenvPython @("-m", "pip", "install", "--upgrade", "pip") "Upgrade pip"
    Invoke-Checked $VenvPython @("-m", "pip", "install", "-r", (Join-Path $SandboxDir "requirements.txt")) "Install requirements.txt"

    Write-Host "[INSTALL] Verifying core Python imports in .venv..."
    Invoke-Checked $VenvPython @(
        "-c",
        "import flask, requests, psutil, pefile, yara, Evtx, mcp; print('[OK] Core Python packages imported successfully.')"
    ) "Verify core Python dependencies"
} catch {
    Write-Host "[ERROR] Python environment setup failed: $_" -ForegroundColor Red
    exit 1
}

# 3. Optional git clone for pure-repo tools while online
if ($CloneGitTools) {
    $GitCmd = Get-Command git -ErrorAction SilentlyContinue
    if (-not $GitCmd) {
        Write-Host "[ERROR] -CloneGitTools requested, but git was not found in PATH." -ForegroundColor Red
        exit 1
    }

    $repos = @(
        @{ Url = "https://github.com/mandiant/capa-rules.git"; Target = "tools\capa-rules" },
        @{ Url = "https://github.com/volatilityfoundation/volatility3.git"; Target = "tools\volatility3" },
        @{ Url = "https://github.com/LaurieWired/GhidraMCP.git"; Target = "tools\GhidraMCP" }
    )
    try {
        foreach ($r in $repos) {
            $dest = Join-Path $SandboxDir $r.Target
            if (Test-Path (Join-Path $dest ".git")) {
                Write-Host "[OK] Repository already cloned: $($r.Target)"
                continue
            }
            if (Test-Path $dest) {
                $existingItems = Get-ChildItem -Path $dest -Force -ErrorAction SilentlyContinue
                if ($existingItems) {
                    throw "Destination '$($r.Target)' already exists and is not empty; remove or clean it before cloning."
                }
                Remove-Item -Path $dest -Force
            }
            Write-Host "[INSTALL] Cloning $($r.Url) -> $($r.Target)..."
            Invoke-Checked $GitCmd.Source @("clone", "--depth", "1", $r.Url, $dest) "Clone $($r.Target)"
        }

        $VolReqs = Join-Path $SandboxDir "tools\volatility3\requirements.txt"
        if (Test-Path $VolReqs) {
            Write-Host "[INSTALL] Installing Volatility 3 Python requirements..."
            Invoke-Checked $VenvPython @("-m", "pip", "install", "-r", $VolReqs) "Install Volatility 3 requirements"
        }

        $GhidraMcpReqs = Join-Path $SandboxDir "tools\GhidraMCP\requirements.txt"
        if (Test-Path $GhidraMcpReqs) {
            Write-Host "[INSTALL] Installing GhidraMCP bridge Python requirements..."
            Invoke-Checked $VenvPython @("-m", "pip", "install", "-r", $GhidraMcpReqs) "Install GhidraMCP requirements"
        }
    } catch {
        Write-Host "[ERROR] Git tool installation failed: $_" -ForegroundColor Red
        exit 1
    }
}

# Create tools\volatility3\symbols ONLY after volatility3 exists (avoids blocking future git clone)
$VolRepoDir = Join-Path $SandboxDir "tools\volatility3"
$VolSymbolsDir = Join-Path $VolRepoDir "symbols"
if ((Test-Path (Join-Path $VolRepoDir "vol.py")) -or (Test-Path (Join-Path $VolRepoDir ".git"))) {
    if (-not (Test-Path $VolSymbolsDir)) {
        New-Item -ItemType Directory -Path $VolSymbolsDir -Force | Out-Null
    }
}

# 4. Prepare local MCP configuration file (mcp\config.json) WITHOUT UTF-8 BOM
$McpExample = Join-Path $SandboxDir "mcp\config.example.json"
$McpTarget = Join-Path $SandboxDir "mcp\config.json"
if ((Test-Path $McpExample) -and (-not (Test-Path $McpTarget))) {
    $rawMcp = Read-Utf8Text -Path $McpExample
    $escapedSandbox = $SandboxDir.Replace("\", "\\")
    $updatedMcp = $rawMcp.Replace("C:\\path\\to\\malbox\\machine3-sandbox", $escapedSandbox)
    Write-Utf8NoBom -Path $McpTarget -Content $updatedMcp
    Write-Host "[OK] Generated local MCP config (UTF-8 without BOM): mcp\config.json"
}

# 5. Auto-discover common tool paths and update config.json WITHOUT UTF-8 BOM
$ConfigPath = Join-Path $SandboxDir "config.json"
$cfgRaw = Read-Utf8Text -Path $ConfigPath
$cfg = $cfgRaw | ConvertFrom-Json

$GhidraHeadless = Get-ChildItem -Path (Join-Path $SandboxDir "tools") -Filter "analyzeHeadless.bat" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
if ($GhidraHeadless) { $cfg.tools.ghidra_headless = $GhidraHeadless }

$SysmonPath = Find-FirstExisting @(
    "C:\Windows\Sysmon64.exe",
    "C:\Windows\Sysmon.exe",
    (Join-Path $SandboxDir "tools\sysinternals\Sysmon64.exe")
)
if ($SysmonPath) { $cfg.tools.sysmon = $SysmonPath }

$ProcmonPath = Find-FirstExisting @(
    (Join-Path $SandboxDir "tools\sysinternals\Procmon64.exe"),
    (Join-Path $SandboxDir "tools\sysinternals\Procmon.exe")
)
if ($ProcmonPath) { $cfg.tools.procmon = $ProcmonPath }

$ProcdumpPath = Find-FirstExisting @(
    (Join-Path $SandboxDir "tools\sysinternals\procdump64.exe"),
    (Join-Path $SandboxDir "tools\sysinternals\procdump.exe")
)
if ($ProcdumpPath) { $cfg.tools.procdump = $ProcdumpPath }

$DumpcapPath = Find-FirstExisting @(
    "C:\Program Files\Wireshark\dumpcap.exe",
    "C:\Program Files (x86)\Wireshark\dumpcap.exe"
)
if ($DumpcapPath) { $cfg.tools.dumpcap = $DumpcapPath }

$TsharkPath = Find-FirstExisting @(
    "C:\Program Files\Wireshark\tshark.exe",
    "C:\Program Files (x86)\Wireshark\tshark.exe"
)
if ($TsharkPath) { $cfg.tools.tshark = $TsharkPath }

$cfgJson = $cfg | ConvertTo-Json -Depth 5
Write-Utf8NoBom -Path $ConfigPath -Content ($cfgJson + "`n")
Write-Host "[OK] Updated discovered tool paths in config.json (UTF-8 without BOM)."

# 6. Dependency Readiness Checklist
Write-Host "`n=== MalBox Machine 3 Dependency Check ===" -ForegroundColor Cyan

$checks = @(
    @{ Name = "FLOSS"; Path = $cfg.tools.floss; Note = "Download release zip -> tools\floss\floss.exe (Python fallback exists)" },
    @{ Name = "capa"; Path = $cfg.tools.capa; Note = "Download release zip -> tools\capa\capa.exe" },
    @{ Name = "capa-rules"; Path = $cfg.tools.capa_rules; Note = "git clone https://github.com/mandiant/capa-rules tools\capa-rules" },
    @{ Name = "YARA CLI (optional)"; Path = $cfg.tools.yara; Note = "yara-python is installed in .venv; optional CLI -> tools\yara\yara64.exe" },
    @{ Name = "Ghidra Headless"; Path = $cfg.tools.ghidra_headless; Note = "Extract official release -> tools\ghidra\ + JDK 17/21" },
    @{ Name = "Sysmon64"; Path = $cfg.tools.sysmon; Note = "Run Admin PS: Sysmon64.exe -accepteula -i configs\sysmon.xml" },
    @{ Name = "Procmon64"; Path = $cfg.tools.procmon; Note = "Extract Sysinternals Suite -> tools\sysinternals\Procmon64.exe" },
    @{ Name = "ProcDump64"; Path = $cfg.tools.procdump; Note = "Extract Sysinternals Suite -> tools\sysinternals\procdump64.exe" },
    @{ Name = "Wireshark dumpcap"; Path = $cfg.tools.dumpcap; Note = "Install Wireshark + Npcap (official installer)" },
    @{ Name = "Wireshark tshark"; Path = $cfg.tools.tshark; Note = "Included with Wireshark installer" },
    @{ Name = "WinPmem (Optional)"; Path = $cfg.tools.winpmem; Note = "Optional full RAM acquisition; disabled by default in config.json" },
    @{ Name = "Volatility 3 (Optional)"; Path = $cfg.tools.volatility3; Note = "Optional offline RAM analysis with pre-cached Windows symbols" }
)

foreach ($item in $checks) {
    $raw = [string]$item.Path
    $resolved = if ([System.IO.Path]::IsPathRooted($raw)) { $raw } else { Join-Path $SandboxDir $raw }
    if (Test-Path $resolved) {
        Write-Host ("  [FOUND]   {0,-24} -> {1}" -f $item.Name, $resolved) -ForegroundColor Green
    } else {
        Write-Host ("  [MISSING] {0,-24} -> {1}" -f $item.Name, $item.Note) -ForegroundColor Yellow
    }
}

# Explicit GhidraMCP multi-stage readiness check (never equate folder existence with working setup)
$GhidraMcpRaw = [string]$cfg.tools.ghidra_mcp_dir
$GhidraMcpResolved = if ([System.IO.Path]::IsPathRooted($GhidraMcpRaw)) { $GhidraMcpRaw } else { Join-Path $SandboxDir $GhidraMcpRaw }
$GhidraMcpBridge = Join-Path $GhidraMcpResolved "bridge_mcp_ghidra.py"
if (Test-Path $GhidraMcpBridge) {
    Write-Host ("  [CLONED]  {0,-24} -> {1}" -f "GhidraMCP (Optional)", "Repo & bridge script present; Ghidra GUI plugin install & runtime NOT verified automatically.") -ForegroundColor Cyan
} elseif (Test-Path $GhidraMcpResolved) {
    Write-Host ("  [INCOMPLETE] {0,-21} -> {1}" -f "GhidraMCP (Optional)", "Directory exists without bridge_mcp_ghidra.py; re-clone or inspect tools\GhidraMCP.") -ForegroundColor Yellow
} else {
    Write-Host ("  [MISSING] {0,-24} -> {1}" -f "GhidraMCP (Optional)", "Optional interactive Ghidra GUI MCP bridge (headless Ghidra works independently).") -ForegroundColor Yellow
}

Write-Host "`n[NEXT MANUAL STEPS BEFORE ISOLATING NETWORK]" -ForegroundColor Cyan
Write-Host "1. Install missing release binaries/installers listed above (see ..\docs\tools-setup.md)."
Write-Host "2. In an Administrator PowerShell, install Sysmon service with MalBox config:"
Write-Host "     .\tools\sysinternals\Sysmon64.exe -accepteula -i .\configs\sysmon.xml"
Write-Host "3. Verify Sysmon service is running: Get-Service Sysmon64"
Write-Host "4. Verify Java & Ghidra Headless if using Ghidra: java -version"
Write-Host "5. Configure Internal Network 2 IP (10.10.20.30/24) and disconnect Internet."
Write-Host "6. Verify sandbox startup and save the Windows 11 CLEAN snapshot."
Write-Host "`nTo start Sandbox server:"
Write-Host "  .\.venv\Scripts\Activate.ps1"
Write-Host "  python sandbox.py"
