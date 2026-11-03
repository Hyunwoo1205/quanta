"""Command-line entry point for Quanta's development foundation."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .registry import ContractRegistry
from .validation import validate_experiment


def _emit(report: dict, output_format: str = "json") -> None:
    if output_format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False))
        return
    print(report["evaluation_status"] if "evaluation_status" in report else ("VALID" if report.get("valid") else "INVALID"))
    if report.get("input_sha256"):
        print("input_sha256: " + report["input_sha256"])
    if report.get("payload") is not None:
        print("energy_j: " + str(report["payload"]["energy_j"]))
        for ident, force in zip(report["particle_ids"], report["payload"]["forces_n"]):
            print(f"force_n[{ident}]: {force}")
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
    sub.add_parser("check-contracts", help="Check bundled schemas, references and registry integrity.")
    sub.add_parser("environment", help="Report actual runtime versions and numerical library configuration.")
    args = parser.parse_args(argv)

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
    try:
        if args.file == "-":
            raw = sys.stdin.buffer.read(1_048_577)
        else:
            with Path(args.file).open("rb") as stream:
                raw = stream.read(1_048_577)
    except OSError as exc:
        report = {"valid": False, "errors": [{"code": "INPUT_READ", "category": "input",
                "path": None, "message": str(exc), "step_id": None, "branch_index": None,
                "retryable": False, "details": {}}], "warnings": [],
                "input_sha256": None, "physical_validation_status": "unvalidated"}
        if args.command == "evaluate":
            report.update(evaluation_status="FAILED", calculation_executed=False, payload=None,
                          report_version="0.1.0", scope="single_configuration_energy_forces")
        _emit(report, args.format)
        return 2
    if args.command == "evaluate":
        from .evaluation import evaluate_experiment
        report = evaluate_experiment(raw)
        _emit(report, args.format)
        return 0 if report["evaluation_status"] == "SUCCEEDED" else 2
    report = validate_experiment(raw)
    _emit(report, args.format)
    return 0 if report["valid"] else 2
