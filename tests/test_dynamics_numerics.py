"""Fixed pre-implementation numerical gates, independent of the VV recurrence."""
import importlib.util
import math
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("quanta_dynamics_numerical_gates",ROOT/"scripts/verify_dynamics.py")
GATES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATES)


@pytest.fixture(scope="module")
def measurements():
    return GATES.measure_cases()


@pytest.mark.parametrize("ident",["D01","D02","D03","D04","D05","D06","D07_drift_segment_subcase"])
def test_fixed_independent_gate_passes(ident,measurements):
    values={case["id"]:case for case in measurements}
    assert ident in values, measurements
    assert values[ident]["status"]=="passed", values[ident]


def test_harmonic_reference_initial_conditions_are_independent():
    positions,velocities=GATES.reference(0)
    assert positions==[[-1,-.25,.75],[1,-.25,.75]]
    assert velocities==[[.125,-.6875,-.03125],[.125,.3125,-.03125]]
    assert GATES.EXACT_E==1.916015625
    assert GATES.EXACT_P==(.5,.25,-.125)
    assert GATES.EXACT_L==(-.15625,.4375,1.75)


@pytest.mark.parametrize("value",[math.nan,math.inf,-math.inf])
def test_independent_comparison_refuses_nonfinite_values(value):
    with pytest.raises(ValueError,match="Nonfinite"):
        GATES._max_difference(value,1.916015625)


def test_reference_grid_refuses_wrong_reported_duration():
    value={"numerics":{"dt_s":.001,"steps":1000}}
    with pytest.raises(ValueError,match="time differs"):
        GATES._check_time({"step_index":100,"time_s":.2},value,1)
