"""strict_json.loads must accept and reject exactly what the original scanner did."""

from __future__ import annotations

import json
import math
import random
import re
from typing import Any

import pytest

from security_lakehouse import strict_json
from security_lakehouse.strict_json import InvalidJSON

_STRUCTURE = re.compile(r'["\[\]{}]')
_STRING_DECODER = json.JSONDecoder()


def _reference_validate(value: Any) -> None:
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > strict_json.MAX_DEPTH:
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


def _reference_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidJSON("duplicate JSON object key")
        result[key] = value
    return result


def _reference_constant(_value: str) -> Any:
    raise InvalidJSON("JSON numbers must be finite")


def _reference_loads(raw: str | bytes) -> Any:
    try:
        text = raw.decode("utf-8-sig") if isinstance(raw, bytes) else raw.removeprefix("﻿")
        depth = position = 0
        while (match := _STRUCTURE.search(text, position)) is not None:
            char = text[match.start()]
            position = match.end()
            if char == '"':
                _, position = _STRING_DECODER.raw_decode(text, match.start())
            elif char in "[{":
                depth += 1
                if depth > strict_json.MAX_DEPTH:
                    raise InvalidJSON("JSON nesting exceeds 64 levels")
            elif char in "]}":
                depth -= 1
        value = json.loads(text, object_pairs_hook=_reference_object, parse_constant=_reference_constant)
        _reference_validate(value)
        return value
    except InvalidJSON:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidJSON("invalid JSON document") from exc


def _outcome(loader: Any, raw: str | bytes) -> tuple[str, str]:
    try:
        value = loader(raw)
    except InvalidJSON:
        return ("reject", "")
    return ("accept", repr(value))


def _assert_same(raw: str | bytes) -> None:
    assert _outcome(strict_json.loads, raw) == _outcome(_reference_loads, raw), raw


def _nest(open_: str, close: str, depth: int, inner: str = "") -> str:
    return open_ * depth + inner + close * depth


VECTORS: list[str | bytes] = [
    b"{broken",
    b'{"status":"fail","status":"pass"}',
    b'{"framework_id":NaN}',
    b'{"framework_id":Infinity}',
    b'{"framework_id":-Infinity}',
    b'{"framework_id":1e400}',
    b'{"framework_id":-1e400}',
    b'{"framework_id":1E309}',
    b'{"framework_id":1e308}',
    b'{"framework_id":' + b"1" + b"0" * 400 + b".0}",
    b'{"framework_id":' + b"1" + b"0" * 400 + b"}",
    b'{"framework_id":' + b"9" * 5000 + b"}",
    b'{"framework_id":"\\ud800"}',
    b'{"framework_id":"\\uDBFF"}',
    b'{"\\udc00":1}',
    b'{"ok":"\\ud83d\\ude00"}',
    b'{"ok":"\\\\ud800"}',
    b'{"nested":{"x":1,"x":2}}',
    b'[{"a":1},{"a":1,"a":1}]',
    b'{"x":' + b"[" * 80 + b"0" + b"]" * 80 + b"}",
    _nest("[", "]", 64),
    _nest("[", "]", 65),
    _nest("[", "]", 64, "0"),
    _nest("[", "]", 65, "0"),
    _nest('{"k":', "}", 64, "0"),
    _nest('{"k":', "}", 65, "0"),
    "[" + ",".join(["[]"] * 70) + "]",
    "[" + ",".join(["{}"] * 70) + "]",
    _nest("[", "]", 5000),
    '{"text":"' + "[{" * 100 + '"}',
    '{"text":"' + "[" * 100 + "\\\\" * 100 + '"}',
    "﻿" + '{"bom":true}',
    "﻿﻿" + '{"bom":true}',
    b'\xef\xbb\xbf{"bom":true}',
    b'{"bad":"\xff"}',
    b'{"cesu":"\xed\xa0\x80"}',
    '{"lone":"\ud800"}',
    '{"lone":"\udfff"}',
    "\ud800",
    '{"ctrl":"\x01"}',
    '{"x":1} trailing',
    '{"x":1}{"y":2}',
    "",
    "   ",
    "null",
    "0",
    "-0",
    "1.5",
    '"NaN"',
    '"Infinity"',
    "true",
    "[1,2,]",
    "{'single':1}",
    '{"a":[1,2,{"b":null,"c":true,"d":false,"e":-0.0,"f":1.5e-10}]}',
    '{"k":"\\u0000\\n\\t\\"\\\\/"}',
    '{"emoji":"😀","cjk":"漢字"}',
]


@pytest.mark.parametrize("raw", VECTORS, ids=range(len(VECTORS)))
def test_loads_matches_reference_on_vectors(raw: str | bytes) -> None:
    _assert_same(raw)
    if isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8")
        except UnicodeEncodeError:
            return
        _assert_same(encoded)


def test_boundary_vectors_still_reject() -> None:
    from test_json_boundaries import INVALID_JSON

    for raw in INVALID_JSON:
        with pytest.raises(InvalidJSON):
            strict_json.loads(raw)
        _assert_same(raw)


_ALPHABET = list('abcXYZ019 _-:/."\\[]{},') + ["é", "漢", "😀", " ", "\x00", "\x1f", "\ud800", "\udc00"]


def _random_string(rng: random.Random) -> str:
    return "".join(rng.choice(_ALPHABET) for _ in range(rng.randint(0, 12)))


def _random_value(rng: random.Random, depth: int) -> Any:
    kind = rng.randint(0, 9 if depth < 6 else 5)
    if kind == 0:
        return None
    if kind == 1:
        return rng.choice([True, False])
    if kind == 2:
        return rng.choice([0, -1, 1, 2**31, -(2**63), 10**30, rng.randint(-(10**9), 10**9)])
    if kind == 3:
        return rng.choice([0.0, -0.0, 0.5, 1e-300, 1.7976931348623157e308, rng.uniform(-1e6, 1e6)])
    if kind in (4, 5):
        return _random_string(rng)
    if kind in (6, 7):
        return [_random_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return {_random_string(rng): _random_value(rng, depth + 1) for _ in range(rng.randint(0, 4))}


def _encodings(value: Any) -> list[str]:
    out = []
    for kwargs in (
        {"sort_keys": True, "separators": (",", ":")},
        {"sort_keys": True, "separators": (",", ":"), "ensure_ascii": False},
        {"indent": 2, "sort_keys": True},
    ):
        out.append(json.dumps(value, **kwargs))
    return out


_MUTATIONS = ["NaN", "Infinity", "-Infinity", "1e999", '"\\ud800"', "[", "]", "{", "}", '"', ",", "\\"]


def _mutate(text: str, rng: random.Random) -> str:
    if not text:
        return text
    choice = rng.randint(0, 4)
    index = rng.randrange(len(text))
    if choice == 0:
        return text[:index]
    if choice == 1:
        return text[:index] + rng.choice(_MUTATIONS) + text[index:]
    if choice == 2:
        return text[:index] + text[index + 1 :]
    if choice == 3 and text.startswith("{") and len(text) > 2:
        match = re.match(r'\{("(?:[^"\\]|\\.)*"):', text)
        if match:
            return "{" + match.group(1) + ":0," + text[1:]
    return text[:index] + rng.choice(_ALPHABET) + text[index:]


def test_loads_matches_reference_on_fuzzed_canonical_rows() -> None:
    rng = random.Random(20261008)
    accepted = rejected = 0
    for _ in range(4000):
        value = _random_value(rng, 0)
        for text in _encodings(value):
            for candidate in (text, _mutate(text, rng), _mutate(_mutate(text, rng), rng)):
                outcome = _outcome(_reference_loads, candidate)
                assert _outcome(strict_json.loads, candidate) == outcome, candidate
                accepted += outcome[0] == "accept"
                rejected += outcome[0] == "reject"
                try:
                    encoded = candidate.encode("utf-8")
                except UnicodeEncodeError:
                    continue
                assert _outcome(strict_json.loads, encoded) == _outcome(_reference_loads, encoded), encoded
    assert accepted > 5000
    assert rejected > 5000


def test_loads_matches_reference_on_pipeline_rows() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    for path in sorted((root / "data").rglob("*.jsonl"))[:40]:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                _assert_same(line)
                _assert_same(line.encode("utf-8"))


@pytest.mark.parametrize(
    "value",
    [
        {"a": [1, {"b": "ok"}]},
        [[[[]]]],
        {"x": float("nan")},
        {"x": [float("inf")]},
        {"x": "\ud800"},
        {"\udc00": 1},
        {1: "nonstring key"},
        {"x": object()},
        {"x": (1, 2)},
        {"x": {1.5: 2}},
    ],
)
def test_validate_matches_reference(value: Any) -> None:
    def outcome(fn: Any) -> str:
        try:
            fn(value)
        except InvalidJSON:
            return "invalid"
        except TypeError:
            return "type"
        return "ok"

    assert outcome(strict_json.validate) == outcome(_reference_validate)


@pytest.mark.parametrize("depth", [63, 64, 65, 66])
@pytest.mark.parametrize("leaf", [None, "s", [], {}])
def test_validate_depth_boundary_matches_reference(depth: int, leaf: Any) -> None:
    value: Any = leaf
    for _ in range(depth):
        value = [value]

    def outcome(fn: Any) -> str:
        try:
            fn(value)
        except InvalidJSON:
            return "invalid"
        return "ok"

    assert outcome(strict_json.validate) == outcome(_reference_validate)


_FULL_VALIDATE = strict_json.validate


def _reference_dumps(value: Any, **kwargs: Any) -> str:
    """The original dumps: a full validation pass, then the standard encoder."""
    _FULL_VALIDATE(value)
    return json.dumps(value, allow_nan=False, **kwargs)


def _dumps_outcome(fn: Any, value: Any, kwargs: dict[str, Any]) -> tuple[str, str]:
    try:
        return ("ok", fn(value, **kwargs))
    except InvalidJSON as exc:
        return ("invalid", str(exc))
    except TypeError:
        return ("type", "")
    except ValueError:
        return ("value", "")


_DUMPS_KWARGS: list[dict[str, Any]] = [
    {},
    {"sort_keys": True, "separators": (",", ":")},
    {"sort_keys": True, "separators": (",", ":"), "ensure_ascii": False},
    {"indent": 2, "sort_keys": True},
    {"ensure_ascii": False},
    {"default": str},
    {"skipkeys": True},
]


class _Key(str):
    pass


def _deep(depth: int, leaf: Any, container: str = "list") -> Any:
    value = leaf
    for _ in range(depth):
        value = [value] if container == "list" else {"k": value}
    return value


def _cyclic() -> Any:
    loop: list[Any] = []
    loop.append(loop)
    return {"x": loop}


_DUMPS_VALUES: list[Any] = [
    None,
    "plain",
    1.5,
    float("nan"),
    "\ud800",
    object(),
    {"a": [1, {"b": "ok"}]},
    {"a": (1, 2, [3])},
    {"x": float("inf")},
    {"x": [float("-inf")]},
    {"x": "\ud800"},
    {"x": "😀"},
    {"x": "😀"},
    {"x": "\\ud800 literal backslash"},
    {"\udc00": 1},
    {1: "int key"},
    {None: "none key"},
    {True: "bool key"},
    {1.5: "float key"},
    {(1, 2): "tuple key"},
    {"a": 1, 2: "mixed keys"},
    {_Key("sub"): "str subclass key"},
    {"x": object()},
    {"x": {1: object()}},
    {"x": [object(), float("nan")]},
    {"x": [float("nan"), object()]},
    {"x": {"y": {2: 3}}},
    _cyclic(),
    _deep(63, 0),
    _deep(64, 0),
    _deep(65, 0),
    _deep(64, []),
    _deep(65, []),
    _deep(64, {}),
    _deep(64, {"k": 1}),
    _deep(64, 0, "dict"),
    _deep(65, 0, "dict"),
    _deep(2000, 0),
    [{"k": "v"}] * 200,
]


@pytest.mark.parametrize("kwargs", _DUMPS_KWARGS, ids=range(len(_DUMPS_KWARGS)))
@pytest.mark.parametrize("value", _DUMPS_VALUES, ids=range(len(_DUMPS_VALUES)))
def test_dumps_matches_reference(value: Any, kwargs: dict[str, Any]) -> None:
    assert _dumps_outcome(strict_json.dumps, value, kwargs) == _dumps_outcome(_reference_dumps, value, kwargs)


def _random_dump_value(rng: random.Random, depth: int) -> Any:
    kind = rng.randint(0, 14 if depth < 6 else 8)
    if kind < 8:
        return _random_value(rng, 6)
    if kind == 8:
        return rng.choice([float("nan"), float("inf"), object(), "\ud800", (1, "t"), "😀", 7])
    if kind in (9, 10, 11):
        return [_random_dump_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    keys: list[Any] = [_random_string(rng) for _ in range(rng.randint(0, 4))]
    if keys and rng.random() < 0.15:
        keys[0] = rng.choice([1, None, True, 2.5, _Key("s")])
    return {key: _random_dump_value(rng, depth + 1) for key in keys}


def test_dumps_matches_reference_on_fuzzed_values() -> None:
    rng = random.Random(20261010)
    outcomes: dict[str, int] = {}
    for _ in range(3000):
        value = _random_dump_value(rng, 0)
        for kwargs in _DUMPS_KWARGS[:5]:
            outcome = _dumps_outcome(_reference_dumps, value, kwargs)
            assert _dumps_outcome(strict_json.dumps, value, kwargs) == outcome, (value, kwargs)
            outcomes[outcome[0]] = outcomes.get(outcome[0], 0) + 1
    assert outcomes.get("ok", 0) > 1000
    assert outcomes.get("invalid", 0) > 500
    assert outcomes.get("type", 0) > 100


def test_dumps_skips_full_validation_for_plain_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []

    def counted(value: Any) -> None:
        calls.append(value)
        _FULL_VALIDATE(value)

    monkeypatch.setattr(strict_json, "validate", counted)
    row = {"event_id": "e", "control_ids": ["A", "B"], "evidence": {"source": "s", "score": 1.5}, "n": None}
    expected = json.dumps(row, sort_keys=True, separators=(",", ":"))
    assert strict_json.dumps(row, sort_keys=True, separators=(",", ":")) == expected
    assert calls == []
    with pytest.raises(InvalidJSON):
        strict_json.dumps({"x": float("nan")})
    assert len(calls) == 1
