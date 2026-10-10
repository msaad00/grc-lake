"""Fuzz the strict JSON boundary every untrusted evidence document passes through.

Invariants:
* ``loads`` either returns a value or raises ``InvalidJSON``; nothing else.
* Bytes and the equivalent text decode to the same value or are both rejected.
* An accepted value passes ``validate`` and round-trips through ``dumps``.
* ``dumps`` accepts exactly the values ``validate`` accepts, raises the same
  exception type when it rejects one, and otherwise matches ``json.dumps``.
"""

from __future__ import annotations

import json
import struct
from typing import Any

from _input import Input, run

from security_lakehouse import strict_json
from security_lakehouse.strict_json import InvalidJSON

_FORMATS: tuple[dict[str, Any], ...] = (
    {},
    {"sort_keys": True},
    {"indent": 2, "ensure_ascii": False},
    {"separators": (",", ":")},
    {"default": str},  # not format-only: always takes the full validation pass
)


def _value(inp: Input, depth: int = 0) -> Any:
    kind = inp.take_int(12) if depth < 6 else inp.take_int(5)
    if kind == 0:
        return None
    if kind == 1:
        return bool(inp.take_int(2))
    if kind == 2:
        return int.from_bytes(inp.take_bytes(16), "little", signed=True)
    if kind == 3:
        return struct.unpack("<d", inp.take_bytes(8).ljust(8, b"\0"))[0]
    if kind == 4:
        return inp.take_text(16)
    if kind in (5, 6):
        items = [_value(inp, depth + 1) for _ in range(inp.take_int(4))]
        return items if kind == 5 else tuple(items)
    if kind == 7:
        return {inp.take_text(8): _value(inp, depth + 1) for _ in range(inp.take_int(4))}
    if kind == 8:
        odd_keys = (None, True, 1, 1.5, float("nan"), "ok")
        return {odd_keys[inp.take_int(len(odd_keys))]: _value(inp, depth + 1)}
    if kind == 9:
        return {1, 2} if inp.take_int(2) else b"bytes"
    nested: Any = _value(inp, depth + 1)
    for _ in range(inp.take_int(80)):
        nested = [nested] if inp.take_int(2) else {"k": nested}
    return nested


def _plain(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    return value


def _check_document(raw: bytes) -> None:
    try:
        value = strict_json.loads(raw)
    except InvalidJSON:
        value = rejected = InvalidJSON
    else:
        rejected = None
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        if rejected is None:
            raise AssertionError("loads accepted bytes that are not UTF-8") from None
        return
    try:
        from_text = strict_json.loads(text)
    except InvalidJSON:
        from_text = InvalidJSON
    if rejected is not None:
        assert from_text is InvalidJSON, "text accepted where the same bytes were rejected"
        return
    assert from_text == value, "text and bytes decoded differently"

    strict_json.validate(value)
    for kwargs in _FORMATS[:4]:
        encoded = strict_json.dumps(value, **kwargs)
        assert strict_json.loads(encoded) == value, "accepted document did not round-trip"


def _check_value(value: Any, kwargs: dict[str, Any]) -> None:
    try:
        strict_json.validate(value)
    except (InvalidJSON, TypeError) as exc:
        expected: type[Exception] | None = type(exc)
    else:
        expected = None
    try:
        encoded = strict_json.dumps(value, **kwargs)
    except (InvalidJSON, TypeError) as exc:
        if expected is None:
            raise AssertionError(f"dumps rejected a value validate accepts: {exc!r}") from exc
        assert type(exc) is expected, f"dumps raised {type(exc).__name__}, validate {expected.__name__}"
        return
    if expected is not None:
        raise AssertionError(f"dumps accepted a value validate rejects with {expected.__name__}")
    assert encoded == json.dumps(value, allow_nan=False, **kwargs)
    if _container_depth(value) > strict_json.MAX_DEPTH:
        # validate() bounds the depth of values and loads() the depth of
        # brackets, so an innermost empty container at value depth 64 is one
        # bracket level past what loads() reads back. Pinned by
        # tests/test_strict_json_equivalence.py; anything deeper must fail.
        assert _container_depth(value) == strict_json.MAX_DEPTH + 1
        try:
            strict_json.loads(encoded)
        except InvalidJSON:
            return
        raise AssertionError("loads accepted more than MAX_DEPTH bracket levels")
    assert strict_json.loads(encoded) == _plain(value), "dumps output did not decode to the value"


def _container_depth(value: Any) -> int:
    """Bracket nesting of ``value``: 0 for a scalar, 1 for ``[]``."""
    depth, level = 0, [value]
    while level := [item for item in level if isinstance(item, (dict, list, tuple))]:
        depth += 1
        level = [child for item in level for child in (item.values() if isinstance(item, dict) else item)]
    return depth


def TestOneInput(data: bytes) -> None:
    inp = Input(data)
    if inp.take_int(2):
        _check_document(inp.take_rest())
        return
    kwargs = _FORMATS[inp.take_int(len(_FORMATS))]
    _check_value(_value(inp), kwargs)


if __name__ == "__main__":
    run(TestOneInput)
