"""Preserve authored signed-zero carriers without changing scientific JCS identity."""
import math

import pytest

from quanta.parsing import parse_json
from quanta.hashing import canonical_bytes


@pytest.mark.parametrize("literal", ["-0", "-0.0", "-0e0", "-0.0e+0"])
def test_authored_negative_zero_survives_strict_json(literal):
    value = parse_json('{"coordinate":' + literal + '}')
    assert math.copysign(1, value["coordinate"]) == -1
    assert canonical_bytes(value) == canonical_bytes({"coordinate": 0})


def test_string_values_and_positive_integers_are_not_rewritten():
    value = parse_json('{"label":"-0","count":12,"zero":0}')
    assert value == {"label": "-0", "count": 12, "zero": 0}
    assert type(value["count"]) is int
    assert math.copysign(1, value["zero"]) == 1
