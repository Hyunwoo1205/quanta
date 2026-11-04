"""Strict, finite, interoperable JSON ingestion without executable coercions."""
from __future__ import annotations

import json
import math
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1
DEFAULT_MAX_BYTES = 1_048_576
MAX_DEPTH = 64


def pointer(parts: list[str | int] | tuple[str | int, ...]) -> str:
    return "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in parts)


class StrictJSONError(ValueError):
    def __init__(self, message: str, path: str | None = None, code: str = "INPUT_SCHEMA"):
        super().__init__(message)
        self.path = path
        self.code = code


def ensure_json_value(value: Any, *, max_depth: int = MAX_DEPTH) -> Any:
    """Return a detached JSON tree, rejecting unsafe numbers and Unicode."""
    ancestors: set[int] = set()

    def visit(item: Any, parts: list[str | int], depth: int) -> Any:
        here = pointer(parts)
        if depth > max_depth:
            raise StrictJSONError("JSON nesting limit exceeded", here, "RESOURCE_LIMIT")
        if item is None or isinstance(item, bool):
            return item
        if isinstance(item, str):
            if any(0xD800 <= ord(ch) <= 0xDFFF for ch in item):
                raise StrictJSONError("Unpaired Unicode surrogate is not permitted", here)
            return item
        if isinstance(item, int):
            if abs(item) > MAX_SAFE_INTEGER:
                try:
                    carrier = float(item)
                except OverflowError as exc:
                    raise StrictJSONError("Integer has no finite lossless binary64 carrier", here) from exc
                if not math.isfinite(carrier) or int(carrier) != item:
                    raise StrictJSONError("Integer cannot be represented losslessly by binary64", here)
                return carrier
            return item
        if isinstance(item, float):
            if not math.isfinite(item):
                raise StrictJSONError("JSON numbers must be finite", here)
            return item
        if not isinstance(item, (dict, list)):
            raise StrictJSONError("Only JSON-native values are accepted", here)
        identity = id(item)
        if identity in ancestors:
            raise StrictJSONError("Cyclic input is not a JSON tree", here)
        ancestors.add(identity)
        try:
            if isinstance(item, dict):
                result = {}
                for key, child in item.items():
                    if not isinstance(key, str):
                        raise StrictJSONError("Object keys must be strings", here)
                    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in key):
                        raise StrictJSONError("Invalid Unicode in an object key", here)
                    visit(key, parts + [key], depth + 1)
                    result[key] = visit(child, parts + [key], depth + 1)
                return result
            else:
                return [visit(child, parts + [i], depth + 1) for i, child in enumerate(item)]
        finally:
            ancestors.remove(identity)

    return visit(value, [], 0)


def parse_json(data: bytes | str | dict, *, max_bytes: int = DEFAULT_MAX_BYTES) -> Any:
    """Decode strict UTF-8 JSON or copy an already-decoded JSON object."""
    if isinstance(data, bytes):
        if len(data) > max_bytes:
            raise StrictJSONError("Input exceeds the byte limit", None, "RESOURCE_LIMIT")
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise StrictJSONError("Input must be valid UTF-8") from exc
    elif isinstance(data, str):
        try:
            size = len(data.encode("utf-8", errors="strict"))
        except UnicodeEncodeError as exc:
            raise StrictJSONError("Invalid Unicode in input text") from exc
        if size > max_bytes:
            raise StrictJSONError("Input exceeds the byte limit", None, "RESOURCE_LIMIT")
        text = data
    elif isinstance(data, dict):
        value = ensure_json_value(data)
        if len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")) > max_bytes:
            raise StrictJSONError("Input exceeds the byte limit", None, "RESOURCE_LIMIT")
        return value
    else:
        raise StrictJSONError("Input must be UTF-8 bytes, JSON text, or an object")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise StrictJSONError("Duplicate object key: " + ascii(key))
            result[key] = value
        return result

    def constant(token: str) -> None:
        raise StrictJSONError("Non-finite JSON literal is not permitted: " + token)

    try:
        # JSON's integer spelling -0 still carries an explicitly authored sign.
        # A float carrier retains it through revisions and fixed-coordinate records.
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant,
                           parse_int=lambda token: -0.0 if token == "-0" else int(token))
    except StrictJSONError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise StrictJSONError("Malformed JSON: " + str(exc)[:180]) from exc
    return ensure_json_value(value)


# Descriptive alias for consumers that prefer an explicit ingestion name.
strict_loads = parse_json
