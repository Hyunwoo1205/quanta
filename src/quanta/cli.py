"""Command-line entry point for Quanta's development foundation."""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
from pathlib import Path

from . import __version__
from .registry import ContractRegistry
from .validation import validate_experiment


def _emit(report: dict, output_format: str = "json") -> None:
    if output_format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False))
        return
    if report.get("scope") in {"synchronous_workflow", "workflow_plan"}:
        result = report.get("result")
        plan = report if report.get("scope") == "workflow_plan" else (report.get("plan") or {})
        print(result["execution_status"] if result else ("PLANNED" if report.get("valid") and not report.get("errors") else "FAILED"))
        if plan.get("resolved_input_sha256"):
            print("resolved_input_sha256: " + plan["resolved_input_sha256"])
        if plan.get("frozen_plan"):
            print("branches: " + str(len(plan["frozen_plan"]["branch_bases"])))
            print("expanded_steps: " + str(len(plan["frozen_plan"]["expanded_steps"])))
        if result:
            print("run_id: " + result["run_id"])
            for field in ("numerical_status", "resolution_status", "partial"):
                print(f"{field}: {result[field]}")
            for step in result["steps"]:
                print(f"step[{step['branch_index']}:{step['step_id']}]: {step['outcome']}")
        for issue in report.get("errors", []) + (result.get("errors", []) if result else []):
            print(f"error: {issue['code']}: {issue['message']}")
        return
    print(report["evaluation_status"] if "evaluation_status" in report else ("VALID" if report.get("valid") else "INVALID"))
    if report.get("input_sha256"):
        print("input_sha256: " + report["input_sha256"])
    if report.get("payload") is not None:
        if report["payload"]["operation"] == "eigenstates":
            print("energies_j: " + str(report["payload"]["energies_j"]))
            print("grid_points_including_boundaries: " + str(len(report["payload"]["x_m"])))
            for field in ("numerical_status", "resolution_status", "partial"):
                print(f"{field}: {report[field]}")
        else:
            print("energy_j: " + str(report["payload"]["energy_j"]))
            for ident, force in zip(report["particle_ids"], report["payload"]["forces_n"]):
                print(f"force_n[{ident}]: {force}")
        if report["payload"]["operation"] == "relax":
            for field in ("free_gradient_inf", "iterations", "evaluations", "stop_reason"):
                print(f"{field}: {report['payload'][field]}")
            print("partial: " + str(report["partial"]))
    for severity in ("errors", "warnings"):
        for issue in report.get(severity, []):
            print(f"{severity[:-1]}: {issue.get('code', 'CHECK')}: "
                  f"{issue.get('path') or '/'}: {issue.get('message', '')}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="quanta", description="Validate experiments and evaluate a supported single configuration."
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="Validate one UTF-8 experiment revision.")
    validate.add_argument("file", help="Path to an experiment JSON file, or - for standard input.")
    validate.add_argument("--format", choices=("json", "text"), default="json")
    evaluate = sub.add_parser("evaluate", help="Calculate pair energy and forces for one initial configuration.")
    evaluate.add_argument("file", help="Single-step experiment JSON, or - for standard input.")
    evaluate.add_argument("--format", choices=("json", "text"), default="json")
    relax = sub.add_parser("relax", help="Search for a stationary configuration with fixed coordinates preserved.")
    relax.add_argument("file", help="Single-step relaxation experiment JSON, or - for standard input.")
    relax.add_argument("--format", choices=("json", "text"), default="json")
    eigenstates = sub.add_parser("eigenstates", help="Calculate low stationary states on a finite one-dimensional domain.")
    eigenstates.add_argument("file", help="Single-step eigenstates experiment JSON, or - for standard input.")
    eigenstates.add_argument("--format", choices=("json", "text"), default="json")
    plan = sub.add_parser("plan", help="Validate and freeze a symbolic multi-step execution plan.")
    plan.add_argument("file", help="Experiment JSON, or - for standard input.")
    plan.add_argument("--format", choices=("json", "text"), default="json")
    run = sub.add_parser("run", help="Execute a validated multi-step experiment synchronously.")
    run.add_argument("file", help="Experiment JSON, or - for standard input.")
    run.add_argument("--output-dir", help="Create a new content-addressed execution bundle directory.")
    run.add_argument("--format", choices=("json", "text"), default="json")
    replay = sub.add_parser("replay", help="Verify a saved bundle and replay with the same frozen implementation.")
    replay.add_argument("directory", help="Existing execution bundle directory.")
    replay.add_argument("--output-dir", help="Create a new replay bundle directory.")
    replay.add_argument("--format", choices=("json", "text"), default="json")
    serve = sub.add_parser("serve", help="Start the authenticated loopback API and one durable numerical worker.")
    serve.add_argument("--store", required=True, help="Private local directory for SQLite service records.")
    serve.add_argument("--port", type=int, default=8765)
    production = sub.add_parser("serve-production", help="Run one loopback ASGI process behind a configured authenticated HTTPS origin.")
    production.add_argument("--store", required=True, help="Private persistent directory for SQLite service records.")
    production.add_argument("--port", type=int, default=8765)
    backup = sub.add_parser("backup-store", help="Create a checked SQLite snapshot in a new directory.")
    backup.add_argument("--store", required=True)
    backup.add_argument("--output", required=True)
    verify_backup = sub.add_parser("verify-backup", help="Check backup bytes, schema and SQLite integrity.")
    verify_backup.add_argument("directory")
    restore = sub.add_parser("restore-store", help="Restore a checked backup to a new store directory.")
    restore.add_argument("directory")
    restore.add_argument("--output", required=True)
    sub.add_parser("check-contracts", help="Check bundled schemas, references and registry integrity.")
    sub.add_parser("environment", help="Report actual runtime versions and numerical library configuration.")
    args = parser.parse_args(argv)

    if args.command in {"backup-store", "verify-backup", "restore-store"}:
        from .backup import BackupError, backup_store, verify_backup, restore_backup
        try:
            if args.command == "backup-store":
                report = backup_store(args.store, args.output)
            elif args.command == "verify-backup":
                report = verify_backup(args.directory)
            else:
                report = restore_backup(args.directory, args.output)
            print(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False))
            return 0
        except (BackupError, OSError) as exc:
            print(str(exc), file=sys.stderr)
            return 2

    if args.command == "serve-production":
        from .access_auth import AccessConfig
        from .owner_token import OwnerTokenConfig
        from .production import create_app
        from .service import ExecutionService
        from .production_server import run_production
        try:
            auth_mode = os.environ.get("QUANTA_AUTH_MODE", "access")
            if auth_mode == "access":
                config = AccessConfig(public_origin=os.environ.get("QUANTA_PUBLIC_ORIGIN", ""),
                    team_domain=os.environ.get("QUANTA_ACCESS_TEAM_DOMAIN", ""),
                    audience=os.environ.get("QUANTA_ACCESS_AUDIENCE", ""),
                    allowed_email=os.environ.get("QUANTA_ALLOWED_EMAIL", ""))
            elif auth_mode == "owner-token":
                config = OwnerTokenConfig(public_origin=os.environ.get("QUANTA_PUBLIC_ORIGIN", ""),
                    token=os.environ.get("QUANTA_OWNER_TOKEN", ""))
            else:
                raise ValueError("The production authentication mode must be access or owner-token")
            if not 0 <= args.port <= 65535:
                raise ValueError("The port must be between 0 and 65535")
            app = create_app(ExecutionService(args.store), config)
            return run_production(app, port=args.port)
        except (OSError, ValueError, RuntimeError) as exc:
            print(str(exc), file=sys.stderr)
            return 2

    if args.command == "serve":
        from .service import ExecutionService
        from .server import create_server
        from .worker import JobWorker
        try:
            service = ExecutionService(args.store)
            server = create_server(service, token=os.environ.get("QUANTA_API_TOKEN", ""), port=args.port)
            previous_signals = {}
            try:
                with JobWorker(service.directory):
                    for signum in (signal.SIGINT, signal.SIGTERM):
                        previous_signals[signum] = signal.signal(signum, signal.default_int_handler)
                    print(f"Quanta API: http://127.0.0.1:{server.server_port}/v1", flush=True)
                    print(f"Quanta workspace: http://127.0.0.1:{server.server_port}/", flush=True)
                    try:
                        server.serve_forever(poll_interval=0.2)
                    except KeyboardInterrupt:
                        pass
            finally:
                server.server_close()
                for signum, previous in previous_signals.items():
                    signal.signal(signum, previous)
            return 0
        except (OSError, ValueError, RuntimeError) as exc:
            print(str(exc), file=sys.stderr)
            return 2

    if args.command == "environment":
        from .environment import environment_report
        report = environment_report()
        _emit(report)
        return 0 if report["valid"] else 2
    if args.command == "check-contracts":
        try:
            registry = ContractRegistry()
            errors = registry.validate_integrity()
        except (OSError, ValueError, TypeError) as exc:
            errors = [{"code": "REGISTRY_SNAPSHOT_UNAVAILABLE", "category": "support",
                       "message": "The bundled contract registry could not be loaded.",
                       "path": None, "step_id": None, "branch_index": None,
                       "retryable": False, "details": {"reason": str(exc)[:200]}}]
        _emit({"valid": not errors, "contract_version": "0.2.0", "errors": errors,
               "physical_validation_status": "unvalidated", "simulation_executed": False})
        return 0 if not errors else 2
    if args.command == "replay":
        from .run_store import replay_bundle
        try:
            report = replay_bundle(args.directory)
        except (OSError, ValueError) as exc:
            report = _workflow_read_failure(exc)
        return _finish_workflow(report, args)
    try:
        if args.file == "-":
            raw = sys.stdin.buffer.read(1_048_577)
        else:
            with Path(args.file).open("rb") as stream:
                raw = stream.read(1_048_577)
    except OSError as exc:
        if args.command in {"plan", "run"}:
            report = _workflow_read_failure(exc, code="INPUT_READ")
            if args.command == "plan":
                report["scope"] = "workflow_plan"
            _emit(report, args.format)
            return 2
        report = {"valid": False, "errors": [{"code": "INPUT_READ", "category": "input",
                "path": None, "message": str(exc), "step_id": None, "branch_index": None,
                "retryable": False, "details": {}}], "warnings": [],
                "input_sha256": None, "physical_validation_status": "unvalidated"}
        if args.command in {"evaluate", "relax", "eigenstates"}:
            quantum = args.command == "eigenstates"
            report.update(evaluation_status="FAILED", calculation_executed=False, payload=None,
                          report_version="0.2.0", partial=False,
                          input_validation_status="failed", resolution_status="not_checked" if quantum else "not_applicable",
                          numerical_status="not_applicable" if args.command == "evaluate" else "not_checked",
                          module_ref=None, provenance=None,
                          scope="single_configuration_eigenstates" if quantum else ("single_configuration_relaxation" if args.command == "relax" else "single_configuration_energy_forces"))
        _emit(report, args.format)
        return 2
    if args.command == "plan":
        from .planning import plan_experiment
        report = plan_experiment(raw)
        _emit({"scope": "workflow_plan", **report}, args.format)
        return 0 if report["valid"] else 2
    if args.command == "run":
        from .workflow import run_experiment
        return _finish_workflow(run_experiment(raw), args)
    if args.command in {"evaluate", "relax", "eigenstates"}:
        from .evaluation import evaluate_experiment, relax_experiment, eigenstates_experiment
        report = {"evaluate": evaluate_experiment, "relax": relax_experiment,
                  "eigenstates": eigenstates_experiment}[args.command](raw)
        _emit(report, args.format)
        return 0 if report["evaluation_status"] == "SUCCEEDED" else 2
    report = validate_experiment(raw)
    _emit(report, args.format)
    return 0 if report["valid"] else 2


def _workflow_read_failure(exc: Exception, *, code: str | None = None) -> dict:
    return {"report_version": "0.1.0", "scope": "synchronous_workflow", "valid": False,
        "result": None, "plan": None, "errors": [{"code": code or getattr(exc, "code", "BUNDLE_INTEGRITY"),
            "category": "input", "message": str(exc)[:300], "path": None, "step_id": None,
            "branch_index": None, "retryable": False, "details": getattr(exc, "details", {})}], "warnings": []}


def _finish_workflow(report: dict, args) -> int:
    stored = True
    if args.output_dir and report.get("plan") is not None:
        from .run_store import write_bundle
        try:
            destination = write_bundle(report, args.output_dir)
            print("bundle: " + str(destination), file=sys.stderr)
        except (OSError, ValueError) as exc:
            stored = False
            report["errors"].append({"code": getattr(exc, "code", "BUNDLE_WRITE"), "category": "runtime",
                "message": str(exc)[:300], "path": None, "step_id": None, "branch_index": None,
                "retryable": False, "details": getattr(exc, "details", {})})
    _emit(report, args.format)
    result = report.get("result")
    return 0 if stored and result and result["execution_status"] == "SUCCEEDED" and not report.get("errors") else 2
