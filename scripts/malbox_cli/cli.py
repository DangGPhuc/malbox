from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .lifecycle import get_status, start_services, stop_services
from .repair import run_doctor

TAG_LABELS = {
    "PASS": "[PASS]",
    "WARN": "[WARN]",
    "FAIL": "[FAIL]",
    "SKIP": "[SKIP]",
}


def find_repo_root(start: Optional[Path] = None) -> Path:
    candidate = (start or Path(__file__).resolve()).resolve()
    for parent in [candidate, *candidate.parents]:
        if (parent / "backend" / "pyproject.toml").is_file() and (parent / "frontend" / "package.json").is_file():
            return parent
    return Path.cwd().resolve()


def _format_doctor_human(report: Dict[str, Any], verbose: bool = False) -> str:
    lines: List[str] = []
    lines.append(f"malbox-ai Doctor ({report['mode']} mode) — Root: {report['root_dir']}")
    lines.append("=" * 72)

    for item in report["checks"]:
        tag = TAG_LABELS.get(item["status"], f"[{item['status']}]")
        repaired_badge = " (repaired)" if item.get("repaired") else ""
        lines.append(f"{tag:<7} {item['name']}{repaired_badge}: {item['summary']}")
        if verbose and item.get("details"):
            lines.append(f"        details: {json.dumps(item['details'], default=str)}")
        if item["status"] in ("FAIL", "WARN") and item.get("remediation"):
            lines.append(f"        fix: {item['remediation']}")

    if report.get("actions_taken"):
        lines.append("-" * 72)
        lines.append("Actions applied:")
        for action in report["actions_taken"]:
            lines.append(f"  * {action}")

    if report.get("errors"):
        lines.append("-" * 72)
        lines.append("Errors:")
        for err in report["errors"]:
            lines.append(f"  ! {err}")

    s = report["summary"]
    lines.append("=" * 72)
    lines.append(
        f"Summary: {report['overall_status']} | "
        f"PASS={s['PASS']} WARN={s['WARN']} FAIL={s['FAIL']} SKIP={s['SKIP']}"
    )
    if report["exit_code"] == 0:
        lines.append("Ready for Replay Mode. Run `./malbox start` to launch services.")
    else:
        lines.append("Diagnostics reported failures. Review `[FAIL]` items above before starting.")

    return "\n".join(lines)


def _format_start_human(res: Dict[str, Any]) -> str:
    if res["exit_code"] != 0:
        lines = [f"[FAIL] {res.get('error', 'Failed to start malbox services')}"]
        if res.get("remediation"):
            lines.append(f"       fix: {res['remediation']}")
        if res.get("log_tail"):
            lines.append("--- Service log tail ---")
            lines.append(res["log_tail"])
        return "\n".join(lines)

    lines = [f"[PASS] malbox-ai started ({res['mode'].upper()} MODE)"]
    for msg in res.get("messages", []):
        lines.append(f"  * {msg}")
    if res.get("backend"):
        lines.append(f"  API URL : {res['backend']['url']}")
        lines.append(f"  API Docs: {res['backend']['docs_url']}")
    if res.get("frontend"):
        lines.append(f"  Web UI  : {res['frontend']['url']}")
    return "\n".join(lines)


def _format_stop_human(res: Dict[str, Any]) -> str:
    lines = ["malbox-ai service shutdown:"]
    for svc, outcome in res.get("services", {}).items():
        lines.append(f"  * {svc:<10}: {outcome}")
    return "\n".join(lines)


def _format_status_human(res: Dict[str, Any]) -> str:
    be = res["backend"]
    fe = res["frontend"]
    lines = [
        f"malbox-ai Status — Active Mode: {res['mode'].upper()} (backend default: {res['default_backend']})",
        f"  Backend : {be['status'].upper():<10} PID={be['pid'] or '-':<7} {be['url']}",
        f"  Frontend: {fe['status'].upper():<10} PID={fe['pid'] or '-':<7} {fe['url']}",
        f"  Logs    : {be['log_file']} | {fe['log_file']}",
    ]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="malbox",
        description="malbox-ai zero-dependency Doctor, Setup, and Service Lifecycle CLI",
    )
    parser.add_argument("--version", action="version", version=f"malbox-ai CLI {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    # doctor
    p_doc = sub.add_parser("doctor", help="Diagnose environment and safely bootstrap/repair Replay Mode")
    mode_grp = p_doc.add_mutually_exclusive_group()
    mode_grp.add_argument("--check", action="store_true", help="Read-only diagnostics (no modifications)")
    mode_grp.add_argument("--repair", action="store_true", help="Check and safely repair missing/broken setup")
    p_doc.add_argument("--json", action="store_true", help="Print machine-readable JSON diagnostics")
    p_doc.add_argument("--verbose", "-v", action="store_true", help="Show detailed metadata per check")
    p_doc.add_argument("--skip-frontend", action="store_true", help="Skip Node.js/npm/frontend checks and setup")
    p_doc.add_argument("--no-build", action="store_true", help="Skip building frontend/dist during setup")
    p_doc.add_argument(
        "--overwrite-env",
        action="store_true",
        help="Reset existing .env from .env.example (requires --yes or interactive confirmation)",
    )
    p_doc.add_argument("--yes", "-y", action="store_true", help="Explicit confirmation for destructive flags")

    # start
    p_start = sub.add_parser("start", help="Start local malbox-ai backend and frontend servers")
    target_grp = p_start.add_mutually_exclusive_group()
    target_grp.add_argument("--backend-only", action="store_true", help="Start only the FastAPI backend")
    target_grp.add_argument("--frontend-only", action="store_true", help="Start only the Vite frontend")
    p_start.add_argument("--wait-seconds", type=int, default=20, help="Health check timeout in seconds (default: 20)")
    p_start.add_argument("--json", action="store_true", help="Print machine-readable JSON output")

    # stop
    p_stop = sub.add_parser("stop", help="Gracefully stop managed malbox-ai services")
    p_stop.add_argument("--timeout", type=float, default=8.0, help="Graceful SIGTERM wait timeout in seconds")
    p_stop.add_argument("--json", action="store_true", help="Print machine-readable JSON output")

    # status
    p_status = sub.add_parser("status", help="Inspect running status and health of malbox-ai services")
    p_status.add_argument("--json", action="store_true", help="Print machine-readable JSON output")

    return parser


def main(argv: Optional[List[str]] = None, root_dir: Optional[Path] = None) -> int:
    if sys.version_info < (3, 10):
        wants_json = "--json" in (argv if argv is not None else sys.argv[1:])
        msg = f"Python 3.10+ is required; found {sys.version.split()[0]}."
        if wants_json:
            print(json.dumps({"overall_status": "FAIL", "exit_code": 1, "error": msg}))
        else:
            print(f"[FAIL] {msg}", file=sys.stderr)
        return 1

    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = (root_dir or find_repo_root()).resolve()

    if args.command == "doctor":
        confirm_overwrite = False
        if args.overwrite_env and (repo_root / ".env").exists():
            if args.yes:
                confirm_overwrite = True
            elif sys.stdin.isatty():
                reply = input("Overwrite existing `.env` with `.env.example`? Existing secrets will be lost [y/N]: ")
                confirm_overwrite = reply.strip().lower() in {"y", "yes"}
            else:
                err_payload = {
                    "mode": "repair",
                    "overall_status": "FAIL",
                    "exit_code": 1,
                    "error": "Refusing to overwrite existing `.env` in non-interactive mode without `--yes`.",
                }
                if args.json:
                    print(json.dumps(err_payload, indent=2))
                else:
                    print(f"[FAIL] {err_payload['error']}", file=sys.stderr)
                return 1

        mode = "check" if args.check else ("repair" if args.repair else "default")
        report = run_doctor(
            repo_root,
            mode=mode,
            skip_frontend=args.skip_frontend,
            confirm_overwrite_env=confirm_overwrite,
            build_frontend=not args.no_build,
        )
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(_format_doctor_human(report, verbose=args.verbose))
        return int(report["exit_code"])

    if args.command == "start":
        res = start_services(
            repo_root,
            backend_only=args.backend_only,
            frontend_only=args.frontend_only,
            wait_seconds=args.wait_seconds,
        )
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(_format_start_human(res))
        return int(res["exit_code"])

    if args.command == "stop":
        res = stop_services(repo_root, timeout=args.timeout)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(_format_stop_human(res))
        return int(res["exit_code"])

    if args.command == "status":
        res = get_status(repo_root)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(_format_status_human(res))
        return int(res["exit_code"])

    return 1
