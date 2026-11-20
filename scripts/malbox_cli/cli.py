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
        tier = f"[{item['readiness_tier']}]" if item.get("readiness_tier") else ""
        tier_str = f"{tier:<13} " if tier else ""
        repaired_badge = " (repaired)" if item.get("repaired") else ""
        lines.append(f"{tag:<7} {tier_str}{item['name']}{repaired_badge}: {item['summary']}")
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
        lines.append("Ready for analysis. Run `./malbox start` to launch services.")
    else:
        lines.append("Diagnostics reported failures. Review `[FAIL]` items above before starting.")

    return "\n".join(lines)


def _format_setup_human(res: Dict[str, Any]) -> None:
    if "matrix" in res:
        print("malbox-ai Deployment Readiness Matrix")
        print("=" * 72)
        for item in res["matrix"]:
            tier = f"[{item.get('tier', 'UNKNOWN')}]"
            tag = TAG_LABELS.get(item["status"], f"[{item['status']}]")
            print(f"{tag:<7} {tier:<13} {item['name']}: {item['summary']}")
            if item.get("remediation") and item["status"] in ("FAIL", "WARN"):
                print(f"        fix: {item['remediation']}")
        print("=" * 72)
        c = res["counts"]
        print(f"Overall: {res['status']} | PASS={c.get('PASS', 0)} WARN={c.get('WARN', 0)} FAIL={c.get('FAIL', 0)} SKIP={c.get('SKIP', 0)}")
        return

    if "profiles" in res:
        print("malbox-ai Hardware & Deployment Planning")
        print("=" * 72)
        print(f"Recommended Profile: {res['recommended_profile']}")
        virt_status = "DETECTED (/dev/kvm accessible)" if res.get("kvm_present") else "NOT DETECTED (Profile A single-host hypervisor disabled)"
        print(f"Hardware Virtualization: {virt_status}")
        print("-" * 72)
        for key, p in res["profiles"].items():
            sup = "[SUPPORTED]" if p.get("supported_on_current_host") else "[UNSUPPORTED ON CURRENT HOST]"
            print(f"\n{p['name']} {sup}")
            print(f"  Description: {p['description']}")
            print(f"  Topology   : {p['network_topology']}")
            print("  Prerequisites:")
            for req in p["prerequisites"]:
                print(f"    * {req}")
            print("  Setup Steps:")
            for cmd in p["setup_commands"]:
                print(f"    $ {cmd}")
        print("\n" + "=" * 72)
        print(f"Next Action: {res.get('next_step')}")
        return

    if "configured_values" in res:
        tag = "[DRY-RUN]" if res.get("dry_run") else "[CONFIGURED]"
        print(f"{tag} malbox subsystem configuration updated successfully:")
        for k, v in res.get("configured_values", {}).items():
            val = "********" if "TOKEN" in k or "KEY" in k else v
            print(f"  * {k} = {val}")
        if res.get("backup_file"):
            print(f"  * Backup created: {res['backup_file']}")
        if res.get("attestation"):
            att = res["attestation"]
            print(f"  * Generated isolation attestation: {att['path']} (0600)")
            print(f"    Machine: {att['machine']} | Route: {att['route']} | Valid: {att['expires_in_days']} days")
        return

    if "critical_issues" in res:
        print(f"malbox-ai Setup Verification: [{res.get('overall_status', 'UNKNOWN')}]")
        print("=" * 72)
        c = res.get("counts", {})
        print(f"Results: PASS={c.get('pass', 0)} WARN={c.get('warn', 0)} FAIL={c.get('fail', 0)} SKIP={c.get('skip', 0)}")
        if res.get("critical_issues"):
            print("-" * 72)
            print("Critical Issues (Blocking Live Detonation):")
            for iss in res["critical_issues"]:
                print(f"  ! {iss}")
        if res.get("warnings"):
            print("-" * 72)
            print("Warnings (Subsystems Degraded):")
            for w in res["warnings"]:
                print(f"  * {w}")
        return

    print(json.dumps(res, indent=2, default=str))


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
    tag = "[FAIL]" if res.get("exit_code", 0) != 0 else "[PASS]"
    lines = [f"{tag} malbox-ai service shutdown ({res.get('status', 'unknown')}):"]
    details = res.get("details", {})
    for svc, outcome in res.get("services", {}).items():
        extra = f" — {details[svc]}" if svc in details and details[svc] else ""
        lines.append(f"  * {svc:<10}: {outcome}{extra}")
    if res.get("errors"):
        lines.append("Errors:")
        for err in res["errors"]:
            lines.append(f"  ! {err}")
    return "\n".join(lines)


def _format_status_human(res: Dict[str, Any]) -> str:
    if res.get("exit_code", 0) != 0:
        errs = "; ".join(res.get("errors", [])) or "Invalid configuration"
        return f"[FAIL] malbox-ai Status ({res.get('status', 'error')}): {errs}"
    be = res["backend"]
    fe = res["frontend"]
    lines = [
        f"malbox-ai Status — Active Mode: {res['mode'].upper()} (backend default: {res['default_backend']})",
        f"  Backend : {be['status'].upper():<12} PID={str(be['pid'] or '-'):<7} {be['url']}",
        f"  Frontend: {fe['status'].upper():<12} PID={str(fe['pid'] or '-'):<7} {fe['url']}",
        f"  Logs    : {be['log_file']} | {fe['log_file']}",
    ]
    if not be.get("verified_ownership") and be.get("pid"):
        lines.append(f"  ! Backend PID warning: {be.get('ownership_reason')}")
    if not fe.get("verified_ownership") and fe.get("pid"):
        lines.append(f"  ! Frontend PID warning: {fe.get('ownership_reason')}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="malbox",
        description="malbox-ai zero-dependency Doctor, Setup, and Service Lifecycle CLI",
    )
    parser.add_argument("--version", action="version", version=f"malbox-ai CLI {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    # doctor
    p_doc = sub.add_parser("doctor", help="Diagnose environment and safely bootstrap/repair Malbox-AI")
    mode_grp = p_doc.add_mutually_exclusive_group()
    mode_grp.add_argument("--check", action="store_true", help="Read-only diagnostics (no modifications)")
    mode_grp.add_argument("--repair", action="store_true", help="Check and safely repair missing/broken setup")
    p_doc.add_argument("--json", action="store_true", help="Print machine-readable JSON diagnostics")
    p_doc.add_argument("--verbose", "-v", action="store_true", help="Show detailed metadata per check")
    p_doc.add_argument("--skip-frontend", action="store_true", help="Skip Node.js/npm/frontend checks and setup")
    p_doc.add_argument("--no-build", action="store_true", help="Skip building frontend/dist during setup")
    p_doc.add_argument(
        "--smoke-test",
        action="store_true",
        help="Run an isolated end-to-end safe intake smoke test (does not detonate malware)",
    )
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

    # setup
    p_setup = sub.add_parser("setup", help="Configure and prepare Malbox subsystems (Profile A/B, Ghidra, CAPE, AI)")
    setup_act = p_setup.add_mutually_exclusive_group()
    setup_act.add_argument("--check", action="store_true", help="Inspect and display readiness matrix")
    setup_act.add_argument("--plan", action="store_true", help="Display actionable Profile A / Profile B deployment plan")
    setup_act.add_argument("--ghidra", action="store_true", help="Configure Ghidra Headless integration")
    setup_act.add_argument("--cape", action="store_true", help="Configure CAPE Sandbox connection & isolation attestation")
    setup_act.add_argument("--ai", action="store_true", help="Configure AI provider (local Ollama, cloud, or mock)")
    setup_act.add_argument("--verify", action="store_true", help="Run post-setup validation checks")
    p_setup.add_argument("--dry-run", action="store_true", help="Show proposed changes without writing .env or files")
    p_setup.add_argument("--json", action="store_true", help="Print machine-readable JSON output")
    p_setup.add_argument("--url", type=str, help="API URL (for CAPE or AI)")
    p_setup.add_argument("--token", type=str, help="API Bearer Token (for CAPE)")
    p_setup.add_argument("--machine", type=str, help="CAPE guest VM machine name (default: win10_malbox)")
    p_setup.add_argument("--route", type=str, help="CAPE network route (default: host-only)")
    p_setup.add_argument("--provider", type=str, help="AI provider name (local, ollama, openai, mock)")
    p_setup.add_argument("--api-key", type=str, help="AI API Key")
    p_setup.add_argument("--model", type=str, help="AI model name")
    p_setup.add_argument("--external-consent", action="store_true", help="Authorize external cloud AI transmission")
    p_setup.add_argument("--ghidra-home", type=str, help="Path to Ghidra installation directory")

    # logs
    p_logs = sub.add_parser("logs", help="View logs from malbox backend and frontend services")
    p_logs.add_argument("--backend", action="store_true", help="Show backend logs only")
    p_logs.add_argument("--frontend", action="store_true", help="Show frontend logs only")
    p_logs.add_argument("-n", "--lines", type=int, default=50, help="Number of recent log lines to display (default: 50)")
    p_logs.add_argument("-f", "--follow", action="store_true", help="Follow log output")

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
        if args.check and args.smoke_test:
            err_msg = "--check is strictly read-only and cannot be combined with --smoke-test."
            if args.json:
                print(json.dumps({"mode": "check", "overall_status": "FAIL", "exit_code": 1, "error": err_msg}, indent=2))
            else:
                print(f"[FAIL] {err_msg}", file=sys.stderr)
            return 1

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

        if args.check:
            mode = "check"
        elif args.repair:
            mode = "repair"
        elif args.smoke_test:
            mode = "smoke"
        else:
            mode = "default"

        report = run_doctor(
            repo_root,
            mode=mode,
            skip_frontend=args.skip_frontend,
            confirm_overwrite_env=confirm_overwrite,
            build_frontend=not args.no_build,
            smoke_test=args.smoke_test,
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

    if args.command == "setup":
        from .setup import setup_ai, setup_cape, setup_check, setup_ghidra, setup_plan, setup_verify

        if args.plan:
            res = setup_plan(repo_root)
        elif args.ghidra:
            res = setup_ghidra(repo_root, ghidra_home=args.ghidra_home, dry_run=args.dry_run)
        elif args.cape:
            res = setup_cape(
                repo_root,
                api_url=args.url,
                api_token=args.token,
                machine=args.machine,
                route=args.route,
                dry_run=args.dry_run,
            )
        elif args.ai:
            res = setup_ai(
                repo_root,
                provider=args.provider or "local",
                base_url=args.url,
                api_key=args.api_key,
                model=args.model,
                external_consent=args.external_consent,
                dry_run=args.dry_run,
            )
        elif args.verify:
            res = setup_verify(repo_root)
        else:
            res = setup_check(repo_root, json_mode=args.json)

        if args.json:
            print(json.dumps(res, indent=2, default=str))
        else:
            _format_setup_human(res)
        return 0

    if args.command == "logs":
        runtime_dir = repo_root / ".malbox"
        be_log = runtime_dir / "backend.log"
        fe_log = runtime_dir / "frontend.log"
        show_be = args.backend or (not args.backend and not args.frontend)
        show_fe = args.frontend or (not args.backend and not args.frontend)
        n = max(1, args.lines)

        if show_be:
            print("=== Backend Logs (.malbox/backend.log) ===")
            if be_log.is_file():
                lines = be_log.read_text(encoding="utf-8", errors="replace").splitlines()
                for line in lines[-n:]:
                    print(line)
            else:
                print("(No backend log file found)")

        if show_fe:
            print("\n=== Frontend Logs (.malbox/frontend.log) ===")
            if fe_log.is_file():
                lines = fe_log.read_text(encoding="utf-8", errors="replace").splitlines()
                for line in lines[-n:]:
                    print(line)
            else:
                print("(No frontend log file found)")
        return 0

    return 1
