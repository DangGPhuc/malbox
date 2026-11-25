# MalBox Machine 3 Tools Directory

Place or clone third-party analysis tools inside this directory **before** disconnecting the Windows 11 VM from the Internet and creating the `CLEAN` snapshot.

Expected layout (adjustable in `machine3-sandbox/config.json`):

- `tools/floss/floss.exe` — Official release binary from https://github.com/mandiant/flare-floss/releases
- `tools/capa/capa.exe` — Official release binary from https://github.com/mandiant/capa/releases
- `tools/capa-rules/` — Git clone of https://github.com/mandiant/capa-rules
- `tools/yara/yara64.exe` — Optional CLI fallback from https://github.com/VirusTotal/yara/releases (`yara-python` is already installed in `.venv`)
- `tools/ghidra/` — Official release archive from https://github.com/NationalSecurityAgency/ghidra/releases (contains `support/analyzeHeadless.bat`)
- `tools/GhidraMCP/` — Git clone / release from https://github.com/LaurieWired/GhidraMCP
- `tools/sysinternals/` — `Sysmon64.exe`, `Procmon64.exe`, `procdump64.exe` from Microsoft Sysinternals
- `tools/winpmem/` — Optional `winpmem.exe` from https://github.com/Velocidex/WinPmem/releases
- `tools/volatility3/` — Git clone of https://github.com/volatilityfoundation/volatility3 plus offline Windows symbols in `tools/volatility3/symbols/`

See `docs/tools-setup.md` for step-by-step download, installation, and verification commands.
