"""Validate experiment contracts without executing a scientific calculation."""
from __future__ import annotations

import copy
import itertools
import math
import re
from fractions import Fraction
from typing import Any

from .autodiff import _fraction_float, _product, _ratio, _sum
from .hashing import definition_sha256
from .parsing import StrictJSONError, parse_json, pointer
from .registry import ContractRegistry

_PAIR = "quanta.pair_static"
_QUANTUM = "quanta.quantum_stationary"
_HBAR = 6.62607015e-34 / (2 * math.pi)
_MAX_ERRORS = 100


def _issue(code: str, message: str, path: str | None = None, *, category: str | None = None,
           step_id: str | None = None, branch_index: int | None = None, details: dict | None = None) -> dict:
    if category is None:
        category = ("resource" if code == "RESOURCE_LIMIT" else "numerical" if code == "EXPRESSION_DOMAIN"
                    else "support" if code in {"MODEL_UNSUPPORTED", "PORT_INCOMPATIBLE", "REPRESENTATION_UNSUPPORTED", "REGISTRY_SNAPSHOT_UNAVAILABLE"}
                    else "input")
    return {"code": code, "category": category, "message": message, "path": path,
            "step_id": step_id, "branch_index": branch_index, "retryable": False, "details": details or {}}


class _Validation:
    def __init__(self, registry: ContractRegistry):
        self.registry = registry
        self.errors: list[dict] = []
        self.warnings: list[dict] = []

    def fail(self, code: str, message: str, path: str | None = None, **context) -> None:
        if len(self.errors) < _MAX_ERRORS:
            self.errors.append(_issue(code, message, path, **context))

    def schema(self, value: Any, ref: str, prefix: str, **context) -> bool:
        initial = len(self.errors)
        try:
            remaining = max(0, _MAX_ERRORS - len(self.errors))
            if remaining == 0:
                return False
            errors = sorted(itertools.islice(self.registry.validator(ref).iter_errors(value), remaining), key=lambda e: (str(list(e.absolute_path)), e.message))
            for error in errors:
                self.fail("INPUT_SCHEMA", error.message[:300], prefix + pointer(tuple(error.absolute_path)), **context)
        except Exception as exc:
            self.fail("REGISTRY_SNAPSHOT_UNAVAILABLE", "Schema validation could not resolve its frozen contract", prefix,
                      details={"reason": str(exc)[:200]}, **context)
        return len(self.errors) == initial

    def ast(self, expression: dict, parameters: dict, capabilities: dict, **context) -> bool:
        initial = len(self.errors)
        nodes = 0
        allowed_variables = set(capabilities.get("variables", []))
        allowed_ops = set(capabilities.get("allowed_ops", []))
        def visit(node: dict, depth: int, path: str):
            nonlocal nodes
            nodes += 1
            if depth > capabilities.get("max_depth", 16) or nodes > capabilities.get("max_nodes", 128):
                self.fail("RESOURCE_LIMIT", "Expression size exceeds the registered limit", path, **context)
                return
            op = node["op"]
            if op not in allowed_ops:
                self.fail("INPUT_SEMANTIC", "Expression operation is not registered", path + "/op", **context)
            if op == "var" and node["name"] not in allowed_variables:
                self.fail("INPUT_SEMANTIC", "Expression variable is not supported by this module", path + "/name", **context)
            if op == "param" and node["name"] not in parameters:
                self.fail("INPUT_SEMANTIC", "Expression parameter is undefined", path + "/name", **context)
            for i, child in enumerate(node.get("args", [])):
                visit(child, depth + 1, path + "/args/" + str(i))
            if "arg" in node:
                visit(node["arg"], depth + 1, path + "/arg")
        visit(expression, 1, "/definition/system/potential/expression")
        if len(parameters) > capabilities.get("max_parameters", 32):
            self.fail("RESOURCE_LIMIT", "Potential parameter count exceeds the registered limit", "/definition/system/potential/parameters", **context)
        return len(self.errors) == initial

    def definition(self, definition: dict, module: dict, *, operation: str | None = None,
                   skip_geometry: bool = False, **context) -> bool:
        initial = len(self.errors)
        if module["module_id"] not in {_PAIR, _QUANTUM}:
            self.fail("MODEL_UNSUPPORTED", "No semantic implementation is available for this registered module", "/definition/system", **context)
            return False
        caps = module["capabilities"]
        try:
            profile = self.registry.resolve_schema(caps["resource_policy_ref"] + "#" + caps["resource_profile_pointer"])
        except ValueError as exc:
            self.fail("REGISTRY_SNAPSHOT_UNAVAILABLE", str(exc), "/definition", **context)
            return False
        if not self.ast_preflight(definition, caps["expression"], profile, **context):
            return False
        if not self.schema(definition, module["definition_schema_ref"], "/definition", **context):
            return False
        # Keep component contracts active even if a future definition schema is less restrictive.
        if not self.schema(definition["system"], module["input_schema_ref"], "/definition/system", **context):
            return False
        if not self.schema(definition["numerics"], module["numerics_schema_ref"], "/definition/numerics", **context):
            return False
        system, numerics = definition["system"], definition["numerics"]
        if definition.get("unit_system") != module["unit_contract"]["interchange_system"]:
            self.fail("INPUT_SEMANTIC", "Unit system differs from the registered module contract", "/definition/unit_system", **context)
        identity = module["module_id"] + "@" + module["module_version"]
        if identity not in profile.get("module_versions", []):
            self.fail("REGISTRY_SNAPSHOT_UNAVAILABLE", "Module is absent from its effective resource profile", "/definition", **context)
            return False
        l0, e0 = definition["scales"]["length_m"], definition["scales"]["energy_j"]
        try:
            force_scale = e0 / l0
            if not math.isfinite(force_scale) or force_scale <= 0:
                raise ValueError
        except (OverflowError, ZeroDivisionError, ValueError):
            self.fail("INPUT_SEMANTIC", "The reduced unit scales are not finite positive binary64 values", "/definition/scales", **context)
            return False
        expression = system["potential"]["expression"]
        parameters = system["potential"]["parameters"]
        expression_caps = copy.deepcopy(caps["expression"])
        for cap_key, profile_key in (("max_depth", "max_ast_depth"), ("max_nodes", "max_ast_nodes"), ("max_parameters", "max_parameters")):
            expression_caps[cap_key] = min(expression_caps[cap_key], profile[profile_key])
        if not self.ast(expression, parameters, expression_caps, **context):
            return False
        values: list[float] = []
        if module["module_id"] == _PAIR:
            particles = system["particles"]
            identifiers = [p["id"] for p in particles]
            if len(identifiers) != len(set(identifiers)):
                self.fail("INPUT_SEMANTIC", "Particle IDs must be unique", "/definition/system/particles", **context)
            if len(particles) > profile["max_particles"]:
                self.fail("RESOURCE_LIMIT", "Particle count exceeds the resource profile", "/definition/system/particles", **context)
            if operation == "relax" and not any(not fixed for p in particles for fixed in p["fixed"]):
                self.fail("INPUT_SEMANTIC", "Relaxation requires at least one free coordinate", "/definition/system/particles", **context)
            if numerics["max_iterations"] > profile["max_optimization_iterations"] or numerics["max_evaluations"] > profile["max_function_gradient_evaluations"]:
                self.fail("RESOURCE_LIMIT", "Optimizer request exceeds the resource profile", "/definition/numerics", **context)
            try:
                reduced = [[x / l0 for x in p["position_m"]] for p in particles]
                if any(not math.isfinite(x) for p in reduced for x in p):
                    raise ValueError
                minimum = system["min_distance_m"] / l0
                if not math.isfinite(minimum) or minimum <= 0:
                    raise ValueError
                if not skip_geometry:
                    for i, particle in enumerate(particles):
                        for j in range(i):
                            distance = math.dist(particle["position_m"], particles[j]["position_m"])
                            rho = distance / l0
                            if not math.isfinite(distance) or distance <= system["min_distance_m"]:
                                self.fail("INPUT_SEMANTIC", "Every pair distance must exceed the minimum distance", "/definition/system/particles", details={"pair_indices": [j, i]}, **context)
                            elif not math.isfinite(rho) or rho <= 0:
                                self.fail("INPUT_SEMANTIC", "Pair distance is outside the finite reduced domain", "/definition/system/particles", details={"pair_indices": [j, i]}, **context)
                            else:
                                values.append(rho)
            except (OverflowError, ZeroDivisionError, ValueError):
                self.fail("INPUT_SEMANTIC", "Coordinates or distances are outside the finite reduced domain", "/definition/system/particles", **context)
        else:
            a, b = system["domain"]["a_m"], system["domain"]["b_m"]
            if not a < b:
                self.fail("INPUT_SEMANTIC", "The domain requires a_m < b_m", "/definition/system/domain", **context)
                return False
            n = int(numerics["n_points"])
            levels = int(numerics["refinement_levels"])
            states = int(numerics["states"])
            finest = (n + 1) * 2**levels - 1
            if finest > profile["max_quantum_points"]:
                self.fail("RESOURCE_LIMIT", "Refined grid exceeds the resource profile", "/definition/numerics/n_points", details={"finest_points": finest}, **context)
            if states > min(profile["max_quantum_states"], n - 2):
                self.fail("INPUT_SEMANTIC", "Requested state count is incompatible with the grid", "/definition/numerics/states", **context)
            if levels > profile["max_quantum_refinement_levels"]:
                self.fail("RESOURCE_LIMIT", "Grid refinement count exceeds the resource profile", "/definition/numerics/refinement_levels", **context)
            try:
                mass = system["mass_kg"]
                # Algebraically equivalent scaling avoids unnecessary squared-unit underflow.
                alpha = (_HBAR / l0) * (_HBAR / mass) / (2 * e0 * l0)
                width = (b - a) / l0
                if not math.isfinite(alpha) or alpha <= 0 or not math.isfinite(width) or width <= 0:
                    raise ValueError
                if finest <= profile["max_quantum_points"]:
                    for level in range(levels + 1):
                        count = (n + 1) * 2**level - 1
                        dx = width / (count + 1)
                        kinetic = alpha / dx / dx
                        if not math.isfinite(dx) or dx <= 0 or not math.isfinite(kinetic) or kinetic <= 0:
                            raise ValueError
                        # Both endpoints are included because the first profile requires a smooth finite potential on its closed domain.
                        values.extend(i * dx for i in range(count + 2))
            except (OverflowError, ZeroDivisionError, ValueError):
                self.fail("INPUT_SEMANTIC", "The reduced domain, kinetic coefficient or grid is not finite positive", "/definition/system/domain", **context)
        if len(self.errors) > initial:
            return False
        try:
            _check_constant_domains(expression, parameters)
            for value in values:
                _evaluate(expression, parameters, value)
        except (ArithmeticError, ValueError) as exc:
            self.fail("EXPRESSION_DOMAIN", "Potential is not finite and defined on an initial evaluation point", "/definition/system/potential/expression", details={"reason": str(exc)[:160]}, **context)
        return len(self.errors) == initial

    def ast_preflight(self, definition: dict, caps: dict, profile: dict, **context) -> bool:
        """Bound AST traversal before recursive oneOf schema evaluation."""
        system = definition.get("system")
        potential = system.get("potential") if isinstance(system, dict) else None
        if not isinstance(potential, dict) or "expression" not in potential:
            return True  # The full registered schema reports structural errors.
        depth_limit = min(caps["max_depth"], profile["max_ast_depth"])
        node_limit = min(caps["max_nodes"], profile["max_ast_nodes"])
        count = 0
        def visit(node, depth):
            nonlocal count
            count += 1
            if depth > depth_limit or count > node_limit:
                return False
            if isinstance(node, dict):
                args = node.get("args")
                if isinstance(args, list):
                    for child in args:
                        if not visit(child, depth + 1):
                            return False
                if "arg" in node and not visit(node["arg"], depth + 1):
                    return False
            return True
        if not visit(potential["expression"], 1):
            self.fail("RESOURCE_LIMIT", "Expression size exceeds the effective registered resource limit", "/definition/system/potential/expression", **context)
            return False
        return True

    def protocol(self, definition: dict, module: dict) -> None:
        protocol = definition["protocol"]
        steps, axes = protocol["steps"], protocol["sweep"]["axes"]
        caps = module["capabilities"]
        profile = self.registry.resolve_schema(caps["resource_policy_ref"] + "#" + caps["resource_profile_pointer"])
        ids = [s["step_id"] for s in steps]
        if len(ids) != len(set(ids)) or "initial" in ids:
            self.fail("INPUT_SEMANTIC", "Step IDs must be unique and cannot use the reserved initial alias", "/definition/protocol/steps")
        max_steps = min(profile["max_protocol_steps"], caps["protocol"]["max_steps"])
        max_axes = min(profile["max_sweep_axes"], caps["protocol"]["max_sweep_axes"])
        max_expanded = min(profile["max_expanded_steps"], caps["protocol"]["max_expanded_steps"])
        if len(steps) > max_steps or len(axes) > max_axes:
            self.fail("RESOURCE_LIMIT", "Protocol exceeds the registered authored-step or sweep-axis limit", "/definition/protocol")
        branches = math.prod(len(a["values"]) for a in axes)
        if branches * len(steps) > max_expanded:
            self.fail("RESOURCE_LIMIT", "Expanded protocol exceeds the resource profile", "/definition/protocol", details={"expanded_steps": branches * len(steps)})
        module_id, module_version = module["module_id"], module["module_version"]
        for i, observable in enumerate(definition["observables"]):
            descriptor = self.registry.get_observable(module_id, module_version, observable)
            if descriptor is None or not any(s["operation"] in descriptor.get("eligible_operations", []) for s in steps):
                self.fail("INPUT_SEMANTIC", "Requested observable has no registered eligible operation in this protocol", "/definition/observables/" + str(i))
        for i, step in enumerate(steps):
            path = "/definition/protocol/steps/" + str(i)
            if step["operation"] not in module["operations"]:
                self.fail("INPUT_SEMANTIC", "Operation is not registered for this module", path + "/operation", step_id=step["step_id"])
            if step["source"] != "initial" and step["source"] not in ids[:i]:
                self.fail("INPUT_SEMANTIC", "Source must be initial or an earlier same-branch step", path + "/source", step_id=step["step_id"])
            if module_id == _QUANTUM and step["source"] != "initial":
                self.fail("PORT_INCOMPATIBLE", "A stationary solution cannot be used as a configuration input", path + "/source", step_id=step["step_id"])
            self.patches(definition, step["overrides"], module_id, path + "/overrides", sweep=False)
        all_axis_paths = [a["path"] for a in axes]
        if _overlapping(all_axis_paths):
            self.fail("INPUT_SEMANTIC", "Sweep target paths must be distinct and non-overlapping", "/definition/protocol/sweep/axes")
        for i, axis in enumerate(axes):
            path = "/definition/protocol/sweep/axes/" + str(i)
            if len(axis["values"]) > profile["max_sweep_values_per_axis"]:
                self.fail("RESOURCE_LIMIT", "Sweep axis exceeds the registered value limit", path + "/values")
            for value in axis["values"]:
                self.patches(definition, [{"path": axis["path"], "value": value}], module_id, path, sweep=True)
        if self.errors:
            return
        choices = itertools.product(*(range(len(a["values"])) for a in axes))
        for branch_index, indices in enumerate(choices):
            base = copy.deepcopy(definition)
            for axis, value_index in zip(axes, indices):
                _assign(base, axis["path"], axis["values"][value_index])
            if not self.definition(base, module, branch_index=branch_index):
                continue
            previous: dict[str, tuple[dict, bool]] = {}
            for step in steps:
                effective, pending = (copy.deepcopy(base), False) if step["source"] == "initial" else (copy.deepcopy(previous[step["source"]][0]), previous[step["source"]][1])
                for patch in step["overrides"]:
                    _assign(effective, patch["path"], patch["value"])
                if pending and _all_positions_overridden(effective, step["overrides"]):
                    pending = False
                self.definition(effective, module, operation=step["operation"], skip_geometry=pending,
                                step_id=step["step_id"], branch_index=branch_index)
                if pending:
                    self.warnings.append(_issue("STATE_DEPENDENT_CHECK_DEFERRED", "Produced coordinates do not exist during contract validation; collision and state-dependent potential checks must run after the source succeeds", "/definition/protocol", category="support", step_id=step["step_id"], branch_index=branch_index))
                previous[step["step_id"]] = (effective, pending or step["operation"] == "relax")

    def patches(self, definition: dict, patches: list[dict], module_id: str, prefix: str, *, sweep: bool) -> None:
        if _overlapping([p["path"] for p in patches]):
            self.fail("INPUT_SEMANTIC", "Patch paths must be distinct and non-overlapping", prefix)
        for i, patch in enumerate(patches):
            path, value = patch["path"], patch["value"]
            here = prefix + ("" if sweep else "/" + str(i))
            if not _allowed_override(path, module_id):
                self.fail("INPUT_SEMANTIC", "Patch target is not permitted by the module contract", here + "/path")
                continue
            try:
                target = _get(definition, path)
            except (KeyError, IndexError, ValueError, TypeError):
                self.fail("INPUT_SEMANTIC", "Patch target does not exist", here + "/path")
                continue
            fixed = "/fixed/" in path
            if fixed:
                valid = not sweep and isinstance(value, bool)
            else:
                valid = isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and isinstance(target, (int, float)) and not isinstance(target, bool)
            if not valid:
                self.fail("INPUT_SEMANTIC", "Patch value does not match the registered target type", here + "/value")


def _evaluate(node: dict, parameters: dict, variable: float) -> float:
    """Safe scalar AST interpretation for input-domain checks, without AD."""
    op = node["op"]
    if op == "const":
        result = float(node["value"])
    elif op == "var":
        result = variable
    elif op == "param":
        result = float(parameters[node["name"]])
    elif op in {"add", "sub", "mul", "div"}:
        args = [_evaluate(arg, parameters, variable) for arg in node["args"]]
        if op == "add":
            result = _sum(args, "/definition/system/potential/expression", "value")
        elif op == "sub":
            result = _sum((args[0], -args[1]), "/definition/system/potential/expression", "value")
        elif op == "mul":
            result = _product(args, "/definition/system/potential/expression", "value")
        else:
            result = _ratio(args[0], args[1], "/definition/system/potential/expression", "value")
    else:
        arg = _evaluate(node["arg"], parameters, variable)
        if op == "pow":
            result = _fraction_float(Fraction(arg) ** int(node["exponent"]), "/definition/system/potential/expression", "value")
        elif op == "neg":
            result = -arg
        else:
            if op == "sqrt" and arg <= 0:
                raise ValueError("sqrt requires a positive argument in the differentiable first profile")
            result = {"exp": math.exp, "log": math.log, "sqrt": math.sqrt, "sin": math.sin, "cos": math.cos}[op](arg)
            if op == "exp" and result == 0.0:
                raise ValueError("Exponential value underflows binary64")
    if not isinstance(result, (int, float)) or not math.isfinite(result):
        raise ValueError("Expression evaluation produced a non-finite value")
    return float(result)


def _check_constant_domains(node: dict, parameters: dict) -> tuple[bool, float | None]:
    """Check state-independent invalid subexpressions even for future states."""
    op = node["op"]
    if op == "var":
        return False, None
    children = node.get("args", [])
    if "arg" in node:
        children = [node["arg"]]
    results = [_check_constant_domains(child, parameters) for child in children]
    if op == "div" and results[1][0] and results[1][1] == 0:
        raise ValueError("Division by a constant zero denominator")
    if all(known for known, _ in results):
        return True, _evaluate(node, parameters, 0.0)
    return False, None


def _tokens(path: str) -> list[str]:
    if not path.startswith("/") or re.search(r"~(?![01])", path):
        raise ValueError("Invalid JSON Pointer")
    return [p.replace("~1", "/").replace("~0", "~") for p in path[1:].split("/")]


def _get(value: Any, path: str) -> Any:
    for token in _tokens(path):
        if isinstance(value, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", token):
                raise ValueError("Invalid array index")
            value = value[int(token)]
        else:
            value = value[token]
    return value


def _assign(definition: dict, path: str, value: Any) -> None:
    tokens = _tokens(path)
    parent = definition
    for token in tokens[:-1]:
        parent = parent[int(token)] if isinstance(parent, list) else parent[token]
    if isinstance(parent, list):
        parent[int(tokens[-1])] = copy.deepcopy(value)
    else:
        parent[tokens[-1]] = copy.deepcopy(value)


def _overlapping(paths: list[str]) -> bool:
    for i, path in enumerate(paths):
        for other in paths[:i]:
            if path == other or path.startswith(other + "/") or other.startswith(path + "/"):
                return True
    return False


def _allowed_override(path: str, module_id: str) -> bool:
    if module_id == _PAIR:
        return bool(re.fullmatch(r"/system/particles/(0|[1-9][0-9]*)/(position_m|fixed)/[012]", path) or
                    re.fullmatch(r"/system/potential/parameters/[A-Za-z][A-Za-z0-9_-]{0,31}", path))
    return bool(path in {"/system/domain/a_m", "/system/domain/b_m", "/system/mass_kg", "/numerics/n_points", "/numerics/states", "/numerics/refinement_levels"} or
                re.fullmatch(r"/system/potential/parameters/[A-Za-z][A-Za-z0-9_-]{0,31}", path))


def _all_positions_overridden(definition: dict, patches: list[dict]) -> bool:
    particles = definition["system"].get("particles", [])
    required = {f"/system/particles/{i}/position_m/{axis}" for i in range(len(particles)) for axis in range(3)}
    return bool(required) and required <= {p["path"] for p in patches}


def validate_experiment(data: bytes | str | dict, *, registry: ContractRegistry | None = None) -> dict:
    """Validate authored input only; no engine, state output or physics claim."""
    report = {"valid": False, "errors": [], "warnings": [], "schema_version": None,
              "module_ref": None, "input_sha256": None, "physical_validation_status": "unvalidated"}
    try:
        experiment = parse_json(data)
    except StrictJSONError as exc:
        report["errors"].append(_issue(exc.code, str(exc), exc.path))
        return report
    if isinstance(experiment, dict):
        report["schema_version"] = experiment.get("schema_version")
    try:
        registry = registry or ContractRegistry()
        integrity = registry.validate_integrity()
    except (OSError, ValueError, TypeError) as exc:
        report["errors"].append(_issue("REGISTRY_SNAPSHOT_UNAVAILABLE", "Frozen contract bundle could not be loaded", details={"reason": str(exc)[:200]}))
        return report
    if integrity:
        report["errors"] = integrity[:_MAX_ERRORS]
        return report
    try:
        # The first parse is a process-wide ingress ceiling. A captured policy
        # may tighten it, and raw text whitespace still counts toward that cap.
        parse_json(data, max_bytes=min(1_048_576, registry.resource_policy["common_execution"]["max_input_bytes"]))
    except StrictJSONError as exc:
        report["errors"].append(_issue(exc.code, str(exc), exc.path))
        return report
    except (KeyError, TypeError, ValueError) as exc:
        report["errors"].append(_issue("REGISTRY_SNAPSHOT_UNAVAILABLE", "Invalid input-byte resource policy", details={"reason": str(exc)[:180]}))
        return report
    validation = _Validation(registry)
    if not validation.schema(experiment, "experiment.schema.json", ""):
        report["errors"] = validation.errors
        return report
    return _finish_definition_validation(experiment["definition"], registry, report, validation)


def _finish_definition_validation(definition: dict, registry: ContractRegistry,
                                  report: dict, validation: _Validation) -> dict:
    if not validation.schema(definition, "experiment.schema.json#/$defs/definition", "/definition"):
        report["errors"] = validation.errors
        return report
    system = definition["system"]
    report["module_ref"] = {"module_id": system["module_id"], "module_version": system["module_version"]}
    module = registry.get_module(system["module_id"], system["module_version"])
    if module is None:
        validation.fail("MODEL_UNSUPPORTED", "The exact module/version is not registered", "/definition/system")
    elif validation.definition(definition, module):
        validation.protocol(definition, module)
        validation.warnings.append(_issue("CONTRACT_VALIDATION_ONLY", "This report validates authored contracts; numerical engines and physical validation have not run", category="support"))
    report["errors"] = validation.errors
    report["warnings"] = validation.warnings
    if not validation.errors:
        try:
            report["input_sha256"] = definition_sha256(definition)
            report["valid"] = True
        except (ValueError, TypeError, OverflowError) as exc:
            report["errors"].append(_issue("INPUT_SCHEMA", "Authored input cannot be represented by the canonical JSON contract", "/definition", details={"reason": str(exc)[:180]}))
    return report


def validate_definition(data: dict, *, registry: ContractRegistry | None = None) -> dict:
    """Validate a definition without inventing experiment or revision identities."""
    report = {"valid": False, "errors": [], "warnings": [], "schema_version": "0.2.0",
              "module_ref": None, "input_sha256": None, "physical_validation_status": "unvalidated"}
    try:
        definition = parse_json(data)
    except StrictJSONError as exc:
        report["errors"].append(_issue(exc.code, str(exc), exc.path))
        return report
    try:
        registry = registry or ContractRegistry()
        integrity = registry.validate_integrity()
        if integrity:
            report["errors"] = integrity[:_MAX_ERRORS]
            return report
        parse_json(data, max_bytes=min(1_048_576, registry.resource_policy["common_execution"]["max_input_bytes"]))
    except StrictJSONError as exc:
        report["errors"].append(_issue(exc.code, str(exc), exc.path))
        return report
    except (OSError, KeyError, ValueError, TypeError) as exc:
        report["errors"].append(_issue("REGISTRY_SNAPSHOT_UNAVAILABLE", "Frozen contract bundle could not be loaded",
                                       details={"reason": str(exc)[:200]}))
        return report
    return _finish_definition_validation(definition, registry, report, _Validation(registry))
