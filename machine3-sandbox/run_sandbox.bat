@echo off
setlocal EnableExtensions

set "SANDBOX_DIR=%~dp0"
pushd "%SANDBOX_DIR%" >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Failed switching to sandbox directory: %SANDBOX_DIR%
    exit /b 1
)

set "VENV_PY=%SANDBOX_DIR%.venv\Scripts\python.exe"
set "SANDBOX_PY=%SANDBOX_DIR%sandbox.py"
set "CONFIG_JSON=%SANDBOX_DIR%config.json"

if not exist "%VENV_PY%" (
    echo [ERROR] Virtual environment Python not found at "%VENV_PY%"
    echo [HINT] Run setup.ps1 first while online.
    popd
    exit /b 1
)

if not exist "%SANDBOX_PY%" (
    echo [ERROR] Missing sandbox entrypoint: "%SANDBOX_PY%"
    popd
    exit /b 1
)

if not exist "%CONFIG_JSON%" (
    echo [ERROR] Missing configuration file: "%CONFIG_JSON%"
    popd
    exit /b 1
)

"%VENV_PY%" -c "import flask, requests, psutil" >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Required Python dependencies are missing or broken in .venv.
    echo [HINT] Run setup.ps1 to repair the environment.
    popd
    exit /b 1
)

"%VENV_PY%" "%SANDBOX_PY%" %*
set "RC=%ERRORLEVEL%"
popd
exit /b %RC%
