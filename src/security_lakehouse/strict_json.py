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
# Once the input text is valid UTF-8, an escaped UTF-16 surrogate is the only
# way a decoded string can carry a lone surrogate.
_SURROGATE_ESCAPE = re.compile(r"\\u[dD][89a-fA-F]")


class InvalidJSON(json.JSONDecodeError):
    """A JSON value cannot be read, stored, or returned safely."""

    def __init__(self, reason: str):
        super().__init__(reason, "", 0)


def _check_scalar(item: Any) -> bool:
    """Validate a non-container value; return False when ``item`` is a container."""
    if isinstance(item, str):
        if not item.isascii():
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise InvalidJSON("JSON contains invalid Unicode") from exc
        return True
    if item is None or isinstance(item, (bool, int)):
        return True
    if isinstance(item, float):
        if not math.isfinite(item):
            raise InvalidJSON("JSON numbers must be finite")
        return True
    if isinstance(item, (dict, list, tuple)):
        return False
    raise TypeError("unsupported JSON value type")


def validate(value: Any) -> None:
    """Reject non-finite numbers, invalid Unicode, keys, types, and deep/cyclic values."""
    if _check_scalar(value):
        return
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        child_depth = depth + 1
        children: Any = item
        if isinstance(item, dict):
            children = item.values()
            for key in item:
                if not isinstance(key, str):
                    raise InvalidJSON("JSON object keys must be strings")
                if child_depth > MAX_DEPTH:
                    raise InvalidJSON("JSON nesting exceeds 64 levels")
                _check_scalar(key)
        for child in children:
            if child_depth > MAX_DEPTH:
                raise InvalidJSON("JSON nesting exceeds 64 levels")
            if not _check_scalar(child):
                pending.append((child, child_depth))


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise InvalidJSON("duplicate JSON object key")
    return result


def _constant(_value: str) -> Any:
    raise InvalidJSON("JSON numbers must be finite")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise InvalidJSON("JSON numbers must be finite")
    return value


_DECODER = json.JSONDecoder(object_pairs_hook=_object, parse_constant=_constant, parse_float=_finite_float)


def _check_depth(text: str) -> None:
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


def loads(raw: str | bytes) -> Any:
    """Decode strict UTF-8 JSON with duplicate-key and bounded-depth checks.

    Every check applies to every input. The cheap tests below only decide
    whether a costlier scan could possibly reject the document.
    """
    try:
        if isinstance(raw, bytes):
            text = raw.decode("utf-8-sig")
        else:
            text = raw.removeprefix("﻿")
            if not text.isascii():
                text.encode("utf-8")
        # Nesting cannot exceed the limit unless the text holds more opening
        # brackets than the limit (bracket characters inside strings included).
        if text.count("[") + text.count("{") > MAX_DEPTH:
            _check_depth(text)
        value = _DECODER.decode(text)
        if _SURROGATE_ESCAPE.search(text) is not None:
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
