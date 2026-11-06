"""Explicit generic-workflow adapter for the frozen standalone dynamics solver.

The generic experiment and standalone solver are distinct contracts.  This
module maps only the approved initial-value science fields, never guesses a
mass, velocity, state conversion or physical time, and preserves the complete
standalone report for the host's separate publication decision.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from typing import Callable

from .autodiff import CalculationError
from .hashing import canonical_bytes


def solver_request(definition: dict) -> dict:
    """Derive the documented 0.3.1 initial request without editing its author."""
    return {"contract_version": "0.3.1", "operation": "integrate",
            "scales": deepcopy(definition["scales"]), "initial_time_s": 0,
            "system": deepcopy(definition["system"]),
            "numerics": deepcopy(definition["numerics"])}


def initial_phase_data(definition: dict) -> dict:
    """The registered full phase state at the authored initial instant."""
    request = solver_request(definition)
    return {"contract_version": "0.3.1", "module_id": "quanta.pair_dynamics",
            "module_version": "0.1.0", "representation": "particles_phase_space_3d",
            "representation_version": "0.1.0", "time_kind": "evolving",
            "time_s": request["initial_time_s"], "scales": request["scales"],
            "system": request["system"]}


def phase_metadata(data: dict | None = None) -> dict:
    """Return the solver's fixed SI/full-step metadata for any phase frame."""
    return {"contract_version": "0.3.1", "position_unit": "m", "velocity_unit": "m/s",
            "mass_unit": "kg", "time_unit": "s", "force_unit": "N", "real_dtype": "float64",
            "finite_only": True, "velocity_time_convention": "synchronized_full_step",
            "physical_validation_status": "unvalidated"}


def validate_solver_report(definition: dict, report: dict) -> None:
    """Check an immediately returned solver report without re-evaluating forces."""
    from .dynamics_results import build_phase_state, check_payload, finalise_report, _same_tree
    from .registry import ContractRegistry

    registry = ContractRegistry(contract_version="0.3.1")
    if registry.validate_integrity():
        raise CalculationError("The standalone solver contract is unavailable",
                               code="REGISTRY_SNAPSHOT_UNAVAILABLE")
    registry.validator("dynamics_report.schema.json").validate(report)
    request = solver_request(definition)
    if report["input_validation_status"] == "pass":
        expected = hashlib.sha256(canonical_bytes(request)).hexdigest()
        if report["input_sha256"] != expected:
            raise CalculationError("Solver report does not bind the derived request", code="ENGINE_FAILURE")
    if report["payload"] is not None:
        check_payload(request, report["payload"], registry=registry,
            execution_status=report["execution_status"], numerical_status=report["numerical_status"],
            resolution_status=report["resolution_status"])
    if report["execution_status"] == "SUCCEEDED":
        expected = build_phase_state(request, report["payload"], registry=registry)
        if not _same_tree(expected, report["final_state"]):
            raise CalculationError("Solver final phase state differs from its primary trajectory",
                                   code="ENGINE_FAILURE")
    if report["provenance"] is not None:
        verified = finalise_report(request, report, registry=registry, provenance=report["provenance"])
        if not _same_tree(verified, report):
            raise CalculationError("Solver publication hashes or byte counts changed", code="ENGINE_FAILURE")


def execute_dynamics(definition: dict, check_deadline: Callable[[], None]) -> dict:
    """Invoke the solver once and preserve host control's original semantics.

    The standalone callback is boolean and deliberately converts callback
    exceptions into engine errors.  The bridge therefore records a host
    refusal, asks the standalone solver to discard unpublished work, then
    re-raises the original host cancellation/resource exception with its exact
    solver report attached.  A workflow must retain the control reason with
    that report; resource refusal is not relabelled as a user cancellation.
    """
    from .dynamics import integrate_dynamics_request

    pending: CalculationError | None = None

    def control() -> bool:
        nonlocal pending
        if pending is not None:
            return True
        try:
            check_deadline()
        except CalculationError as exc:
            pending = exc
            return True
        except Exception as exc:
            pending = CalculationError("Trusted workflow control failed", code="ENGINE_FAILURE",
                details={"exception_type": type(exc).__name__})
            return True
        return False

    report = integrate_dynamics_request(solver_request(definition), check_cancel=control)
    if pending is not None:
        pending.dynamics_solver_report = report
        pending.dynamics_control_error = {"code": pending.code, "message": str(pending),
                                          "path": pending.path, "details": deepcopy(pending.details)}
        raise pending
    return report
