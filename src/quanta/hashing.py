"""RFC 8785 canonical bytes and the authored-definition identity."""
from __future__ import annotations

import hashlib
from typing import Any

import rfc8785

from .parsing import ensure_json_value

_DEFINITION_MEMBERS = frozenset({"unit_system", "scales", "system", "numerics", "protocol", "observables", "extensions"})


def canonical_bytes(value: Any) -> bytes:
    """Produce JCS bytes with no fallback serializer or Unicode normalization."""
    return rfc8785.dumps(ensure_json_value(value))


def definition_sha256(definition: dict) -> str:
    """Hash the complete validated authored definition, excluding its envelope."""
    if not isinstance(definition, dict):
        raise TypeError("An authored definition must be an object")
    if set(definition) - _DEFINITION_MEMBERS:
        raise ValueError("Definition contains unregistered top-level members")
    return hashlib.sha256(canonical_bytes(definition)).hexdigest()
