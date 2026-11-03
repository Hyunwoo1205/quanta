"""Forward differentiation of the bounded, registered distance-expression AST.

Every node produces a binary64 value and tangent. Domain errors and nonzero
results outside the binary64 range raise CalculationError; no finite-difference
or clipping fallback is used. Exact zero tangents avoid unnecessary reciprocals.
"""

from __future__ import annotations

import math
import re
from fractions import Fraction
from typing import Iterable


_EXPRESSION_PATH = "/definition/system/potential/expression"
_PARAMETER_PATH = "/definition/system/potential/parameters"
_PARAMETER_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}\Z")


class CalculationError(ValueError):
    """A structured failure in an expression or numerical calculation."""

    def __init__(self, message: str, *, code: str = "EXPRESSION_DOMAIN",
                 path: str = _EXPRESSION_PATH, details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.path = path
        self.details = details or {}


def _number(value: object, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CalculationError("Expected a finite binary64 number", code="INPUT_SEMANTIC", path=path)
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise CalculationError("Number is outside the binary64 range", code="INPUT_SEMANTIC", path=path) from exc
    if not math.isfinite(result) or (isinstance(value, int) and int(result) != value):
        raise CalculationError("Number has no exact finite binary64 carrier", code="INPUT_SEMANTIC", path=path)
    return result


def _range_error(path: str, quantity: str) -> CalculationError:
    return CalculationError(f"{quantity} is outside the finite nonzero binary64 range", path=path,
                            details={"quantity": quantity, "precision": "binary64"})


def _fraction_float(value: Fraction, path: str, quantity: str = "result") -> float:
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise _range_error(path, quantity) from exc
    if not math.isfinite(result) or (value and result == 0.0):
        raise _range_error(path, quantity)
    return result


def _product(values: Iterable[float], path: str, quantity: str = "product") -> float:
    # An exact local accumulator prevents overflow/underflow in arbitrary factor
    # order and preserves a genuine zero factor. The node result is binary64.
    result = Fraction(1)
    for value in values:
        result *= Fraction(value)
    return _fraction_float(result, path, quantity)


def _sum(values: Iterable[float], path: str, quantity: str = "sum") -> float:
    values = list(values)
    try:
        result = math.fsum(values)
    except OverflowError:
        # fsum can overflow an intermediate partial even if cancellation leaves
        # a representable sum; exact fallback retains that cancellation.
        return _fraction_float(sum(map(Fraction, values), Fraction()), path, quantity)
    if not math.isfinite(result):
        raise _range_error(path, quantity)
    return result


def _ratio(numerator: float, denominator: float, path: str, quantity: str = "quotient") -> float:
    if denominator == 0.0:
        raise CalculationError("Division by zero", path=path)
    return _fraction_float(Fraction(numerator) / Fraction(denominator), path, quantity)


def value_and_derivative(expression: dict, parameters: dict, rho: float) -> tuple[float, float]:
    """Return f(rho), f'(rho) from one registered AST, without mutating inputs.

    Limits are depth 16, nodes 128, parameters 32 and integer powers -12..12.
    Malformed input, domain violations, overflow and nonzero underflow raise a
    CalculationError. Each intermediate node's value and tangent must be finite.
    """
    rho = _number(rho, _EXPRESSION_PATH + "/rho")
    if not isinstance(parameters, dict):
        raise CalculationError("Parameters must be an object", code="INPUT_SEMANTIC", path=_PARAMETER_PATH)
    if len(parameters) > 32:
        raise CalculationError("Parameter limit exceeded", code="RESOURCE_LIMIT", path=_PARAMETER_PATH)
    normalized_parameters = {}
    for name, value in parameters.items():
        if not isinstance(name, str) or not _PARAMETER_NAME.fullmatch(name):
            raise CalculationError("Invalid parameter name", code="INPUT_SEMANTIC", path=_PARAMETER_PATH)
        normalized_parameters[name] = _number(value, _PARAMETER_PATH + "/" + name)
    nodes = 0

    def malformed(message: str, path: str) -> CalculationError:
        return CalculationError(message, code="INPUT_SEMANTIC", path=path)

    def visit(node: object, path: str, depth: int) -> tuple[float, float]:
        nonlocal nodes
        nodes += 1
        if depth > 16 or nodes > 128:
            raise CalculationError("Expression resource limit exceeded", code="RESOURCE_LIMIT", path=path)
        if not isinstance(node, dict) or not isinstance(node.get("op"), str):
            raise malformed("Expression node must declare an operation", path)
        op = node["op"]
        keys = {"const": {"op", "value"}, "var": {"op", "name"}, "param": {"op", "name"},
                "add": {"op", "args"}, "mul": {"op", "args"}, "sub": {"op", "args"},
                "div": {"op", "args"}, "pow": {"op", "arg", "exponent"},
                **{name: {"op", "arg"} for name in ("neg", "exp", "log", "sqrt", "sin", "cos")}}
        if op not in keys or set(node) != keys[op]:
            raise malformed("Unsupported operation or expression fields", path)
        if op == "const":
            return _number(node["value"], path + "/value"), 0.0
        if op == "var":
            if node["name"] != "rho":
                raise malformed("Only the registered rho variable is supported", path + "/name")
            return rho, 1.0
        if op == "param":
            name = node["name"]
            if not isinstance(name, str) or name not in normalized_parameters:
                raise malformed("Expression refers to an undefined parameter", path + "/name")
            return normalized_parameters[name], 0.0
        if op in ("add", "mul", "sub", "div"):
            args = node["args"]
            valid_arity = isinstance(args, list) and ((2 <= len(args) <= 8) if op in ("add", "mul") else len(args) == 2)
            if not valid_arity:
                raise malformed("Invalid operation arity", path + "/args")
            pairs = [visit(arg, f"{path}/args/{index}", depth + 1) for index, arg in enumerate(args)]
            values, tangents = zip(*pairs)
            if op == "add":
                return _sum(values, path, "value"), _sum(tangents, path, "tangent")
            if op == "sub":
                return _sum((values[0], -values[1]), path, "value"), _sum((tangents[0], -tangents[1]), path, "tangent")
            if op == "mul":
                value = _product(values, path, "value")
                # Product rule without division by factors: zeros and cancellation
                # are exact locally, including a zero value with nonzero tangent.
                tangent = Fraction()
                for index, seed in enumerate(tangents):
                    if seed == 0.0:
                        continue
                    term = Fraction(seed)
                    for other, factor in enumerate(values):
                        if other != index:
                            term *= Fraction(factor)
                    tangent += term
                return value, _fraction_float(tangent, path, "tangent")
            a, b = values
            da, db = tangents
            value = _ratio(a, b, path, "value")
            if da == 0.0 and db == 0.0:
                return value, 0.0
            tangent = (Fraction(da) * Fraction(b) - Fraction(a) * Fraction(db)) / (Fraction(b) ** 2)
            return value, _fraction_float(tangent, path, "tangent")
        value, seed = visit(node["arg"], path + "/arg", depth + 1)
        if op == "pow":
            exponent = node["exponent"]
            if (isinstance(exponent, bool) or not isinstance(exponent, (int, float))
                    or not -12 <= exponent <= 12 or int(exponent) != exponent):
                raise malformed("Power requires an integer exponent in -12..12", path + "/exponent")
            exponent = int(exponent)
            if exponent == 0:
                return 1.0, 0.0
            if value == 0.0 and exponent < 0:
                raise CalculationError("Zero cannot have a negative power", path=path)
            result = _fraction_float(Fraction(value) ** exponent, path, "value")
            tangent = Fraction() if seed == 0.0 else exponent * Fraction(value) ** (exponent - 1) * Fraction(seed)
            return result, _fraction_float(tangent, path, "tangent")
        if op == "neg":
            return -value, -seed
        if op in ("log", "sqrt") and value <= 0.0:
            raise CalculationError(f"{op} requires a strictly positive argument", path=path)
        try:
            result = getattr(math, op)(value)
        except (OverflowError, ValueError) as exc:
            raise CalculationError(f"{op} exceeds its numerical domain", path=path) from exc
        if not math.isfinite(result) or (op == "exp" and result == 0.0):
            raise _range_error(path, "value")
        if seed == 0.0:
            return result, 0.0
        if op == "exp":
            tangent = _product((result, seed), path, "tangent")
        elif op == "log":
            tangent = _ratio(seed, value, path, "tangent")
        elif op == "sqrt":
            tangent = _fraction_float(Fraction(seed) / (2 * Fraction(result)), path, "tangent")
        elif op == "sin":
            tangent = _product((math.cos(value), seed), path, "tangent")
        else:  # cos
            tangent = _product((-math.sin(value), seed), path, "tangent")
        return result, tangent

    return visit(expression, _EXPRESSION_PATH, 1)
