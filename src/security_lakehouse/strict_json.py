"""Dependency-free JSON boundaries for untrusted evidence and durable writes.

Canonical hashing of historical artifacts is intentionally unchanged.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any

MAX_DEPTH = 64
# Search only for structural characters; let the JSON decoder scan strings
# without a backtracking expression over untrusted input.
_STRUCTURE = re.compile(r'["\[\]{}]')
_STRING_DECODER = json.JSONDecoder()


class InvalidJSON(json.JSONDecodeError):
    """A JSON value cannot be read, stored, or returned safely."""

    def __init__(self, reason: str):
        super().__init__(reason, "", 0)


def validate(value: Any) -> None:
    """Reject non-finite numbers, invalid Unicode, keys, types, and deep/cyclic values."""
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > MAX_DEPTH:
            raise InvalidJSON("JSON nesting exceeds 64 levels")
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise InvalidJSON("JSON contains invalid Unicode") from exc
        elif item is None or isinstance(item, (bool, int)):
            continue
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise InvalidJSON("JSON numbers must be finite")
        elif isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise InvalidJSON("JSON object keys must be strings")
                pending.append((key, depth + 1))
                pending.append((child, depth + 1))
        elif isinstance(item, (list, tuple)):
            pending.extend((child, depth + 1) for child in item)
        else:
            raise TypeError("unsupported JSON value type")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidJSON("duplicate JSON object key")
        result[key] = value
    return result


def _constant(_value: str) -> Any:
    raise InvalidJSON("JSON numbers must be finite")


def loads(raw: str | bytes) -> Any:
    """Decode strict UTF-8 JSON with duplicate-key and bounded-depth checks."""
    try:
        text = raw.decode("utf-8-sig") if isinstance(raw, bytes) else raw.removeprefix("\ufeff")
        depth = position = 0
        while (match := _STRUCTURE.search(text, position)) is not None:
            char = text[match.start()]
            position = match.end()
            if char == '"':
                # Invoke the decoder only at quotes, never at a container that
                # has not yet passed the depth guard.
                _, position = _STRING_DECODER.raw_decode(text, match.start())
            elif char in "[{":
                depth += 1
                if depth > MAX_DEPTH:
                    raise InvalidJSON("JSON nesting exceeds 64 levels")
            elif char in "]}":
                depth -= 1
        value = json.loads(text, object_pairs_hook=_object, parse_constant=_constant)
        validate(value)
        return value
    except InvalidJSON:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidJSON("invalid JSON document") from exc


def dumps(value: Any, **kwargs: Any) -> str:
    """Serialize only validated values; callers retain their existing formatting."""
    validate(value)
    return json.dumps(value, allow_nan=False, **kwargs)
