"""Independent value/derivative references for the registered scalar AST."""

import copy
import math

import pytest

from quanta.autodiff import value_and_derivative


def c(value):
    return {"op": "const", "value": value}


def v():
    return {"op": "var", "name": "rho"}


def unary(op, arg):
    return {"op": op, "arg": arg}


def binary(op, left, right):
    return {"op": op, "args": [left, right]}


def power(arg, exponent):
    return {"op": "pow", "arg": arg, "exponent": exponent}


@pytest.mark.parametrize("expression,expected_value,expected_derivative", [
    (c(4.2), lambda r: 4.2, lambda r: 0),
    (v(), lambda r: r, lambda r: 1),
    ({"op": "param", "name": "k"}, lambda r: 2.3, lambda r: 0),
    ({"op": "add", "args": [v(), c(0.3), unary("sin", v())]},
     lambda r: r + 0.3 + math.sin(r), lambda r: 1 + math.cos(r)),
    ({"op": "mul", "args": [v(), v(), c(2)]}, lambda r: 2*r*r, lambda r: 4*r),
    (binary("sub", power(v(), 3), c(0.7)), lambda r: r**3 - 0.7, lambda r: 3*r*r),
    (binary("div", unary("exp", v()), binary("add", v(), c(2))),
     lambda r: math.exp(r)/(r+2), lambda r: math.exp(r)*(r+1)/(r+2)**2),
    (unary("neg", v()), lambda r: -r, lambda r: -1),
    (unary("exp", v()), math.exp, math.exp),
    (unary("log", v()), math.log, lambda r: 1/r),
    (unary("sqrt", v()), math.sqrt, lambda r: 0.5/math.sqrt(r)),
    (unary("sin", v()), math.sin, math.cos),
    (unary("cos", v()), math.cos, lambda r: -math.sin(r)),
])
def test_each_registered_operation_against_analytic_reference(expression, expected_value, expected_derivative):
    for rho in (0.4, 1.3, 2.1):
        value, derivative = value_and_derivative(expression, {"k": 2.3}, rho)
        assert value == pytest.approx(expected_value(rho), rel=2e-14, abs=2e-14)
        assert derivative == pytest.approx(expected_derivative(rho), rel=2e-14, abs=2e-14)


@pytest.mark.parametrize("exponent", [-12, -3, -1, 0, 1, 2, 12])
def test_integer_powers_include_negative_base_and_zero_exponent(exponent):
    rho = 1.3
    expression = power(unary("neg", v()), exponent)
    expected_derivative = 0 if exponent == 0 else -exponent*(-rho)**(exponent-1)
    value, derivative = value_and_derivative(expression, {}, rho)
    assert value == pytest.approx((-rho)**exponent, rel=2e-14, abs=2e-14)
    assert derivative == pytest.approx(expected_derivative, rel=2e-14, abs=2e-14)


@pytest.mark.parametrize("expression,expected", [
    (power(v(), 0), (1, 0)),
    (power(v(), 1), (0, 1)),
    (power(v(), 2), (0, 0)),
    (binary("sub", v(), v()), (0, 0)),
    (binary("div", c(0), c(1e300)), (0, 0)),
    (c(0), (0, 0)),
    ({"op": "mul", "args": [v(), c(2), c(3)]}, (0, 6)),
    ({"op": "mul", "args": [v(), v(), c(3)]}, (0, 0)),
    ({"op": "mul", "args": [v(), c(0), v()]}, (0, 0)),
])
def test_zero_safe_powers_and_products(expression, expected):
    assert value_and_derivative(expression, {}, 0) == pytest.approx(expected, abs=0)


def test_nested_chain_and_quotient_rule_with_parameters_does_not_mutate_input():
    denominator = binary("add", unary("sqrt", v()), unary("log", binary("add", v(), c(2))))
    expression = binary("add", binary("div", unary("exp", unary("sin", v())), denominator),
                        binary("mul", {"op": "param", "name": "k"},
                               power(binary("sub", v(), {"op": "param", "name": "rho0"}), -2)))
    parameters = {"k": 0.8, "rho0": -0.3}
    original = copy.deepcopy((expression, parameters))
    for rho in (0.5, 1.4, 2.7):
        d = math.sqrt(rho) + math.log(rho+2)
        dp = 0.5/math.sqrt(rho) + 1/(rho+2)
        expected_value = math.exp(math.sin(rho))/d + 0.8/(rho+0.3)**2
        expected_derivative = (math.exp(math.sin(rho))*(math.cos(rho)*d-dp)/d**2
                               - 1.6/(rho+0.3)**3)
        actual = value_and_derivative(expression, parameters, rho)
        assert actual == pytest.approx((expected_value, expected_derivative), rel=3e-14, abs=3e-14)
    assert (expression, parameters) == original


@pytest.mark.parametrize("expression,rho", [
    (binary("div", c(1), c(0)), 1),
    (unary("log", c(0)), 1),
    (unary("log", c(-1)), 1),
    (unary("sqrt", c(0)), 1),
    (unary("sqrt", c(-1)), 1),
    (power(v(), -1), 0),
    (unary("exp", c(1000)), 1),
    # exp(709.6) is finite; its chain-rule derivative 2*exp(709.6) is not.
    (unary("exp", binary("mul", c(2), v())), 354.8),
    (binary("mul", c(0), unary("log", c(-1))), 1),
    (power(unary("log", c(-1)), 0), 1),
])
def test_invalid_domain_and_nonfinite_value_or_derivative_are_errors(expression, rho):
    with pytest.raises(ValueError):
        value_and_derivative(expression, {}, rho)


@pytest.mark.parametrize("expression,parameters,rho", [
    ({"op": "eval", "text": "rho*rho"}, {}, 1),
    ({"op": "var", "name": "xi"}, {}, 1),
    ({"op": "param", "name": "missing"}, {}, 1),
    ({"op": "const", "value": True}, {}, 1),
    ({"op": "var", "name": "rho", "extra": 1}, {}, 1),
    ({"op": "sub", "args": [v()]}, {}, 1),
    (power(v(), 13), {}, 1),
    (power(v(), -13), {}, 1),
    (power(v(), True), {}, 1),
    (v(), {}, True),
    (v(), {}, math.inf),
    (v(), {"k": math.nan}, 1),
    (v(), {"k": True}, 1),
])
def test_direct_api_rejects_malformed_ast_and_invalid_numbers(expression, parameters, rho):
    with pytest.raises(ValueError):
        value_and_derivative(expression, parameters, rho)


def test_direct_api_enforces_registered_ast_and_parameter_resource_bounds():
    deep = v()
    for _ in range(17):
        deep = unary("neg", deep)
    broad = {"op": "add", "args": [
        {"op": "add", "args": [{"op": "add", "args": [c(1) for _ in range(8)]}
                                  for _ in range(8)]} for _ in range(2)]}
    for expression, parameters in ((deep, {}), (broad, {}), (v(), {f"p{i}": 1 for i in range(33)})):
        with pytest.raises(ValueError):
            value_and_derivative(expression, parameters, 1)


def test_exact_registered_ast_depth_node_and_parameter_limits_remain_usable():
    depth16 = v()
    for _ in range(15):
        depth16 = unary("neg", depth16)
    assert value_and_derivative(depth16, {}, 1) == (-1, -1)
    tree = c(1)
    for _ in range(6):
        tree = binary("add", copy.deepcopy(tree), copy.deepcopy(tree))
    # Full binary tree: 127 nodes; the final unary node makes exactly 128.
    assert value_and_derivative(unary("neg", tree), {}, 1) == (-64, 0)
    assert value_and_derivative(v(), {f"p{i}": 1 for i in range(32)}, 1) == (1, 1)
    with pytest.raises(ValueError):
        value_and_derivative(unary("neg", depth16), {}, 1)


@pytest.mark.parametrize("expression,rho", [
    (binary("mul", c(1e-200), c(1e-200)), 1),
    (binary("div", c(1e-200), c(1e200)), 1),
    (unary("exp", c(-1000)), 1),
    (power(c(1e-200), 2), 1),
    # The primal value is exactly zero, but its mathematically nonzero tangent
    # cannot be represented. Zero primal factors must not hide tangent loss.
    ({"op": "mul", "args": [c(1e-200), c(1e-200), binary("sub", v(), c(1))]}, 1),
])
def test_nonzero_value_or_derivative_underflow_is_not_silently_returned_as_zero(expression, rho):
    with pytest.raises(ValueError):
        value_and_derivative(expression, {}, rho)
