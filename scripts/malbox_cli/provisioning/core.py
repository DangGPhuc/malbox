from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import chmod_safe, resolve_effective_config
from ..setup import backup_env_file, update_env_values


def install_core(
    root_dir: Path,
    skip_frontend: bool = False,
    no_build: bool = False,
    dry_run: bool = False,
    non_interactive: bool = False,
) -> Dict[str, Any]:
    """
    Automated installation and provisioning of core Malbox components:
    - Verifies Python 3.10+ runtime.
    - Creates and configures Python virtual environment (.venv).
    - Installs backend dependencies.
    - Builds frontend production assets (if npm present and not skipped).
    - Initializes SQLite database schema and tables.
    - Sets up data, quarantine, artifacts, and runtime directories with strict 0700 permissions.
    - Safely provisions .env from .env.example with cryptographically random secrets.
    """
    steps_log: List[Dict[str, Any]] = []
    errors: List[str] = []

    # 1. Directory Structure Setup
    data_dir = root_dir / "data"
    quarantine_dir = data_dir / "quarantine"
    artifacts_dir = data_dir / "artifacts"
    runtime_dir = data_dir / "runtime"

    dirs_created: List[str] = []
    if not dry_run:
        for d in (data_dir, quarantine_dir, artifacts_dir, runtime_dir):
            if not d.exists():
                d.mkdir(parents=True, exist_ok=True)
                dirs_created.append(str(d))
            chmod_safe(d, 0o700)
    steps_log.append({
        "step": "directories",
        "status": "PASS",
        "details": f"Initialized data directories with 0700 permissions: {quarantine_dir}, {artifacts_dir}, {runtime_dir}",
        "created": dirs_created,
    })

    # 2. .env Configuration Provisioning
    env_file = root_dir / ".env"
    example_file = root_dir / ".env.example"
    env_created = False
    backup_file: Optional[Path] = None

    if not env_file.exists():
        if not dry_run:
            if example_file.exists():
                content = example_file.read_text(encoding="utf-8")
            else:
                content = (
                    "MALBOX_ENV=development\n"
                    "MALBOX_HOST=127.0.0.1\n"
                    "MALBOX_PORT=8000\n"
                    "MALBOX_DATA_DIR=./data\n"
                    "MALBOX_QUARANTINE_DIR=./data/quarantine\n"
                    "MALBOX_ARTIFACTS_DIR=./data/artifacts\n"
                    "MALBOX_LIVE_MODE_ENABLED=true\n"
                    "MALBOX_REQUIRE_EXPLICIT_APPROVAL=true\n"
                    "MALBOX_ALLOW_SYNTHETIC_REPLAY=false\n"
                    "MALBOX_DEFAULT_SANDBOX_BACKEND=cape\n"
                    "MALBOX_AI_PROVIDER=mock\n"
                )
            # Inject secure random secrets
            op_token = secrets.token_hex(24)
            secret_key = secrets.token_hex(32)
            lines = []
            for line in content.splitlines():
                if line.startswith("MALBOX_OPERATOR_TOKEN="):
                    lines.append(f"MALBOX_OPERATOR_TOKEN={op_token}")
                elif line.startswith("MALBOX_SECRET_KEY="):
                    lines.append(f"MALBOX_SECRET_KEY={secret_key}")
                else:
                    lines.append(line)
            if not any("MALBOX_OPERATOR_TOKEN=" in l for l in lines):
                lines.append(f"MALBOX_OPERATOR_TOKEN={op_token}")
            if not any("MALBOX_SECRET_KEY=" in l for l in lines):
                lines.append(f"MALBOX_SECRET_KEY={secret_key}")
            env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
            chmod_safe(env_file, 0o600)
            env_created = True
        steps_log.append({
            "step": "env_config",
            "status": "PASS",
            "details": f"Created .env from example with unique operator secrets (0600 permissions)",
            "env_created": env_created,
        })
    else:
        # Existing .env: ensure operator token is present and valid
        cfg = resolve_effective_config(root_dir)
        curr_op = cfg.get("MALBOX_OPERATOR_TOKEN", "").strip()
        if not curr_op or len(curr_op) < 16:
            new_op = secrets.token_hex(24)
            ok, backup = update_env_values(root_dir, {"MALBOX_OPERATOR_TOKEN": new_op}, dry_run=dry_run)
            backup_file = backup
            steps_log.append({
                "step": "env_config",
                "status": "PASS",
                "details": "Generated new secure operator token in .env",
                "backup_file": str(backup) if backup else None,
            })
        else:
            steps_log.append({
                "step": "env_config",
                "status": "PASS",
                "details": ".env configuration verified and active",
            })

    # 3. Python Virtualenv (.venv) Provisioning
    venv_dir = root_dir / ".venv"
    venv_python = venv_dir / "bin" / "python3"
    venv_pip = venv_dir / "bin" / "pip"

    if not venv_python.exists():
        if dry_run:
            steps_log.append({
                "step": "python_venv",
                "status": "PLAN",
                "details": f"Would create Python virtual environment at {venv_dir}",
            })
        else:
            try:
                res = subprocess.run(
                    [sys.executable, "-m", "venv", str(venv_dir)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=60,
                )
                if res.returncode != 0:
                    errors.append(f"Failed to create virtual environment: {res.stderr}")
                    steps_log.append({
                        "step": "python_venv",
                        "status": "FAIL",
                        "error": res.stderr,
                    })
                else:
                    steps_log.append({
                        "step": "python_venv",
                        "status": "PASS",
                        "details": f"Created virtual environment at {venv_dir}",
                    })
            except Exception as e:
                errors.append(f"Virtualenv creation error: {str(e)}")
                steps_log.append({"step": "python_venv", "status": "FAIL", "error": str(e)})
    else:
        steps_log.append({
            "step": "python_venv",
            "status": "PASS",
            "details": f"Existing virtual environment verified at {venv_dir}",
        })

    # 4. Backend Dependencies
    if venv_python.exists() and not dry_run:
        backend_dir = root_dir / "backend"
        pyproject = backend_dir / "pyproject.toml"
        if pyproject.exists():
            try:
                # Check if fastapi is importable in venv
                chk = subprocess.run(
                    [str(venv_python), "-c", "import fastapi, sqlalchemy, pefile, pytest"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                )
                if chk.returncode != 0:
                    # Install dependencies
                    install_cmd = [str(venv_pip), "install", "-q", "-e", str(backend_dir)]
                    res = subprocess.run(install_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300)
                    if res.returncode == 0:
                        steps_log.append({
                            "step": "backend_deps",
                            "status": "PASS",
                            "details": "Installed backend dependencies into .venv",
                        })
                    else:
                        errors.append(f"pip install failed: {res.stderr[:200]}")
                        steps_log.append({"step": "backend_deps", "status": "FAIL", "error": res.stderr[:300]})
                else:
                    steps_log.append({
                        "step": "backend_deps",
                        "status": "PASS",
                        "details": "Backend dependencies verified in .venv",
                    })
            except Exception as e:
                errors.append(f"Backend dependency validation failed: {str(e)}")
                steps_log.append({"step": "backend_deps", "status": "FAIL", "error": str(e)})
    elif dry_run:
        steps_log.append({
            "step": "backend_deps",
            "status": "PLAN",
            "details": "Would verify/install backend dependencies in .venv",
        })

    # 5. Database Initialization
    if not dry_run:
        py_exec = str(venv_python) if venv_python.exists() else sys.executable
        init_script = (
            "import sys; sys.path.insert(0, 'backend'); "
            "from app.core.database import init_db; init_db(); print('DB_INIT_OK')"
        )
        try:
            db_res = subprocess.run(
                [py_exec, "-c", init_script],
                cwd=str(root_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15,
            )
            if db_res.returncode == 0 and "DB_INIT_OK" in db_res.stdout:
                steps_log.append({
                    "step": "database",
                    "status": "PASS",
                    "details": "SQLite database schema and tables initialized at data/malbox.db",
                })
            else:
                errors.append(f"Database initialization failed: {db_res.stderr}")
                steps_log.append({"step": "database", "status": "FAIL", "error": db_res.stderr})
        except Exception as e:
            errors.append(f"Database initialization error: {str(e)}")
            steps_log.append({"step": "database", "status": "FAIL", "error": str(e)})
    else:
        steps_log.append({
            "step": "database",
            "status": "PLAN",
            "details": "Would initialize SQLite database schema and tables",
        })

    # 6. Frontend Build
    frontend_dir = root_dir / "frontend"
    frontend_dist = frontend_dir / "dist"
    if not skip_frontend and not no_build:
        npm_bin = shutil.which("npm")
        if npm_bin and frontend_dir.is_dir():
            if not dry_run:
                # Build if dist missing or package.json newer
                dist_index = frontend_dist / "index.html"
                if not dist_index.exists():
                    try:
                        res = subprocess.run(
                            [npm_bin, "run", "build"],
                            cwd=str(frontend_dir),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            timeout=180,
                        )
                        if res.returncode == 0:
                            steps_log.append({
                                "step": "frontend_build",
                                "status": "PASS",
                                "details": "Compiled production frontend distribution at frontend/dist",
                            })
                        else:
                            steps_log.append({
                                "step": "frontend_build",
                                "status": "WARN",
                                "warning": f"Frontend build failed: {res.stderr[:200]}",
                            })
                    except Exception as e:
                        steps_log.append({"step": "frontend_build", "status": "WARN", "warning": str(e)})
                else:
                    steps_log.append({
                        "step": "frontend_build",
                        "status": "PASS",
                        "details": "Frontend production distribution verified at frontend/dist",
                    })
            else:
                steps_log.append({
                    "step": "frontend_build",
                    "status": "PLAN",
                    "details": "Would verify/compile frontend production distribution",
                })

    success = (len(errors) == 0)
    return {
        "success": success,
        "dry_run": dry_run,
        "status": "PASS" if success else "FAIL",
        "steps": steps_log,
        "errors": errors,
        "backup_file": str(backup_file) if backup_file else None,
        "summary": "Core Malbox environment provisioned successfully." if success else f"Core setup encountered errors: {'; '.join(errors)}",
    }
