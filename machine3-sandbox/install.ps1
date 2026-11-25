<#
.SYNOPSIS
    Prepares MalBox Machine 3 Windows 11 Sandbox Python environment, folders, MCP config, and checks tools.
.DESCRIPTION
    Run this script BEFORE isolating the VM from the Internet and BEFORE taking the CLEAN snapshot.
    Pass -CloneGitTools to git clone open-source repositories (capa-rules, volatility3, GhidraMCP) into .\tools\.
#>
param(
    [switch]$CloneGitTools
)

$ErrorActionPreference = "Stop"
$SandboxDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $SandboxDir

Write-Host "[INSTALL] Initializing MalBox Machine 3 Sandbox in $SandboxDir..." -ForegroundColor Cyan

# 1. Create required folders
$dirs = @(
    "workspace",
    "evidence",
    "tools",
    "tools\floss",
    "tools\capa",
    "tools\yara",
    "tools\sysinternals",
    "tools\winpmem",
    "tools\volatility3\symbols",
    "scripts\yara_rules"
)
foreach ($d in $dirs) {
    $full = Join-Path $SandboxDir $d
    if (-not (Test-Path $full)) {
        New-Item -ItemType Directory -Path $full -Force | Out-Null
    }
}

# 2. Create Python virtual environment and install dependencies
$PythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    $PythonCmd = Get-Command py -ErrorAction SilentlyContinue
}
if (-not $PythonCmd) {
    Write-Host "[ERROR] Python 3.10+ not found in PATH. Install Python first." -ForegroundColor Red
    exit 1
}

$VenvDir = Join-Path $SandboxDir ".venv"
if (-not (Test-Path $VenvDir)) {
    Write-Host "[INSTALL] Creating Python virtual environment..."
    & $PythonCmd.Source -m venv $VenvDir
}

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$VenvPip = Join-Path $VenvDir "Scripts\pip.exe"

Write-Host "[INSTALL] Installing Python dependencies from requirements.txt..."
& $VenvPython -m pip install --upgrade pip
& $VenvPip install -r (Join-Path $SandboxDir "requirements.txt")

# 3. Optional git clone for pure-repo tools while online
if ($CloneGitTools) {
    $GitCmd = Get-Command git -ErrorAction SilentlyContinue
    if (-not $GitCmd) {
        Write-Host "[WARN] git not found; skipping repository cloning." -ForegroundColor Yellow
    } else {
        $repos = @(
            @{ Url = "https://github.com/mandiant/capa-rules.git"; Target = "tools\capa-rules" },
            @{ Url = "https://github.com/volatilityfoundation/volatility3.git"; Target = "tools\volatility3" },
            @{ Url = "https://github.com/LaurieWired/GhidraMCP.git"; Target = "tools\GhidraMCP" }
        )
        foreach ($r in $repos) {
            $dest = Join-Path $SandboxDir $r.Target
            if (-not (Test-Path (Join-Path $dest ".git"))) {
                Write-Host "[INSTALL] Cloning $($r.Url) -> $($r.Target)..."
                & $GitCmd.Source clone --depth 1 $r.Url $dest
            } else {
                Write-Host "[OK] Repository already cloned: $($r.Target)"
            }
        }
        $VolReqs = Join-Path $SandboxDir "tools\volatility3\requirements.txt"
        if (Test-Path $VolReqs) {
            Write-Host "[INSTALL] Installing Volatility 3 requirements..."
            & $VenvPip install -r $VolReqs
        }
    }
}

# 4. Prepare local MCP configuration file (mcp\config.json) from example
$McpExample = Join-Path $SandboxDir "mcp\config.example.json"
$McpTarget = Join-Path $SandboxDir "mcp\config.json"
if ((Test-Path $McpExample) -and (-not (Test-Path $McpTarget))) {
    $rawMcp = Get-Content $McpExample -Raw
    $escapedSandbox = $SandboxDir.Replace("\", "\\")
    $updatedMcp = $rawMcp.Replace("C:\\path\\to\\malbox\\machine3-sandbox", $escapedSandbox)
    Set-Content -Path $McpTarget -Value $updatedMcp -Encoding UTF8
    Write-Host "[OK] Generated local MCP config: mcp\config.json"
}

# 5. Auto-discover common tool paths and update config.json if detected
$ConfigPath = Join-Path $SandboxDir "config.json"
$cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json

function Find-FirstExisting([string[]]$Candidates) {
    foreach ($c in $Candidates) {
        if ($c -and (Test-Path $c)) {
            return $c
        }
    }
    return $null
}

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

$cfg | ConvertTo-Json -Depth 5 | Set-Content -Path $ConfigPath -Encoding UTF8
Write-Host "[OK] Updated discovered tool paths in config.json"

# 6. Dependency Readiness Checklist
Write-Host "`n=== MalBox Machine 3 Dependency Check ===" -ForegroundColor Cyan

$checks = @(
    @{ Name = "FLOSS"; Path = $cfg.tools.floss; Note = "Download release zip -> tools\floss\floss.exe (Python fallback exists)" },
    @{ Name = "capa"; Path = $cfg.tools.capa; Note = "Download release zip -> tools\capa\capa.exe" },
    @{ Name = "capa-rules"; Path = $cfg.tools.capa_rules; Note = "git clone https://github.com/mandiant/capa-rules tools\capa-rules" },
    @{ Name = "Ghidra Headless"; Path = $cfg.tools.ghidra_headless; Note = "Extract official release -> tools\ghidra\ + JDK 17/21" },
    @{ Name = "GhidraMCP"; Path = $cfg.tools.ghidra_mcp_dir; Note = "Optional interactive MCP bridge: tools\GhidraMCP" },
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

Write-Host "`n[NEXT MANUAL STEPS BEFORE ISOLATING NETWORK]" -ForegroundColor Cyan
Write-Host "1. Install missing release binaries/installers listed above (see ..\docs\tools-setup.md)."
Write-Host "2. In an Administrator PowerShell, install Sysmon service with MalBox config:"
Write-Host "     Sysmon64.exe -accepteula -i configs\sysmon.xml"
Write-Host "3. Verify Sysmon service is running: Get-Service Sysmon64"
Write-Host "4. Configure Internal Network 2 IP (10.10.20.30/24) and disconnect Internet."
Write-Host "5. Start sandbox server and save the Windows 11 CLEAN snapshot."
Write-Host "`nTo start Sandbox server:"
Write-Host "  .\.venv\Scripts\Activate.ps1"
Write-Host "  python sandbox.py"
