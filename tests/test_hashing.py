"""RFC 8785 expectations are independent of the selected implementation.

Official reference, checked 2026-11-03:
https://www.rfc-editor.org/rfc/rfc8785.html sections 3.2.2--3.2.4, Appendix B.
These are serialization tests, not scientific numerical acceptance cases.
"""

import hashlib
import json
import math
import struct

import pytest

from quanta.hashing import canonical_bytes, definition_sha256
from quanta.validation import validate_experiment


def test_rfc8785_section_3_2_2_complete_vector():
    source = r'''{
      "numbers": [333333333.33333329, 1E30, 4.50,
                  2e-3, 0.000000000000000000000000001],
      "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
      "literals": [null, true, false]
    }'''
    expected = bytes.fromhex(
        "7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c"
        "226e756d62657273223a5b3333333333333333332e333333333333332c3165"
        "2b33302c342e352c302e3030322c31652d32375d2c22737472696e67223a22"
        "e282ac245c75303030665c6e4127425c225c5c5c5c5c222f227d"
    )
    assert canonical_bytes(json.loads(source)) == expected


def test_rfc8785_appendix_b_ieee754_boundary_vectors():
    vectors = [
        ("0000000000000000", "0"),
        ("8000000000000000", "0"),
        ("0000000000000001", "5e-324"),
        ("8000000000000001", "-5e-324"),
        ("7fefffffffffffff", "1.7976931348623157e+308"),
        ("ffefffffffffffff", "-1.7976931348623157e+308"),
        ("4340000000000000", "9007199254740992"),
        ("4430000000000000", "295147905179352830000"),
        ("44b52d02c7e14af5", "9.999999999999997e+22"),
        ("44b52d02c7e14af6", "1e+23"),
        ("44b52d02c7e14af7", "1.0000000000000001e+23"),
        ("444b1ae4d6e2ef4f", "999999999999999900000"),
        ("444b1ae4d6e2ef50", "1e+21"),
        ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
        ("3eb0c6f7a0b5ed8d", "0.000001"),
        ("43143ff3c1cb0959", "1424953923781206.2"),
    ]
    for bits, expected in vectors:
        value = struct.unpack(">d", bytes.fromhex(bits))[0]
        assert canonical_bytes(value) == expected.encode(), bits


def test_rfc8785_sorting_uses_utf16_code_units_recursively():
    # Astral U+1F600 sorts before U+FB33 in UTF-16, unlike Python code points.
    value = {"\u20ac": 5, "\r": 1, "\ufb33": 7, "1": 2,
             "\U0001f600": 6, "\u0080": 3, "\u00f6": 4}
    expected = '{"\\r":1,"1":2,"\u0080":3,"ö":4,"€":5,"😀":6,"דּ":7}'
    assert canonical_bytes(value) == expected.encode("utf-8")
    assert canonical_bytes([value, {"z": 1, "a": 2}]) == (
        b"[" + expected.encode("utf-8") + b',{"a":2,"z":1}]'
    )


def test_jcs_preserves_unicode_without_normalizing():
    assert canonical_bytes({"s": "é"}) != canonical_bytes({"s": "e\u0301"})
    assert canonical_bytes({"s": "é"}) == '{"s":"é"}'.encode()


def test_jcs_rejects_nonfinite_values_and_invalid_unicode():
    for value in (math.nan, math.inf, -math.inf, {"bad": "\ud800"}, {"\udfff": 1}):
        with pytest.raises(ValueError):
            canonical_bytes(value)


def test_definition_hash_is_sha256_of_complete_authored_definition(pair):
    definition = pair["definition"]
    expected = hashlib.sha256(canonical_bytes(definition)).hexdigest()
    assert definition_sha256(definition) == expected
    assert validate_experiment(pair)["input_sha256"] == expected


def test_revision_metadata_is_excluded_but_protocol_is_hash_content(pair):
    original = validate_experiment(pair)["input_sha256"]
    pair["title"] = "Different metadata"
    pair["revision_id"] = "55e55555-5555-4555-8555-555555555555"
    pair["created_at"] = "2026-11-04T00:00:00Z"
    assert validate_experiment(pair)["input_sha256"] == original
    pair["definition"]["protocol"]["steps"][1]["source"] = "initial"
    report = validate_experiment(pair)
    assert report["valid"] is True, report
    assert report["input_sha256"] != original


def test_hash_equivalent_json_spellings_and_property_order(pair):
    original = validate_experiment(pair)
    pretty = json.dumps(pair, ensure_ascii=True, indent=2).replace('"k": 2,', '"k": 2.0,')
    reversed_keys = dict(reversed(list(pair.items())))
    assert original["valid"] is True
    assert validate_experiment(pretty.encode())["input_sha256"] == original["input_sha256"]
    assert validate_experiment(reversed_keys)["input_sha256"] == original["input_sha256"]


def test_exact_large_binary64_value_survives_canonical_json_reingest(pair):
    pair["definition"]["system"]["potential"]["expression"] = {"op": "const", "value": 1e16}
    scientific_json = json.dumps(pair)
    canonical_json = canonical_bytes(pair)
    assert "1e+16" in scientific_json
    assert b'"value":10000000000000000' in canonical_json
    scientific_report = validate_experiment(scientific_json)
    canonical_report = validate_experiment(canonical_json)
    assert scientific_report["valid"] is True, scientific_report
    assert canonical_report["valid"] is True, canonical_report
    assert scientific_report["input_sha256"] == canonical_report["input_sha256"]
    # Exact binary64 values remain admissible even when canonical spelling
    # becomes an integer token larger than the safe-integer interval.
    direct = {"large": 1e16}
    assert canonical_bytes(json.loads(canonical_bytes(direct))) == canonical_bytes(direct)
