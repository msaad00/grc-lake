"""Display provenance from explicit source markers, never identity or lake names.

A positive result means the input contains synthetic evidence. A negative result
only means no marker was found; it does not authenticate provider origin.
"""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from security_lakehouse import strict_json
from security_lakehouse.generations import pinned_path
from security_lakehouse.io import iter_jsonl

_MAX_SOURCE_BYTES = 128 * 1024 * 1024
_MAX_CACHE_ENTRIES = 32
_cache: OrderedDict[tuple[str, bytes], bool] = OrderedDict()
_cache_lock = threading.Lock()


def _explicit_synthetic(row: dict[str, Any]) -> bool:
    attrs = row.get("attributes")
    return row.get("source") == "synthetic-audit-fixture" or (
        isinstance(attrs, dict) and (attrs.get("demo") is True or attrs.get("synthetic") is True)
    )


def _bronze_rows_contain_synthetic(rows: Iterable[dict[str, Any]]) -> bool:
    return any(isinstance(row.get("raw"), dict) and _explicit_synthetic(row["raw"]) for row in rows)


def contains_synthetic_evidence(lake: Path, normalized_events: Iterable[dict[str, Any]] = ()) -> bool:
    """Check normalized markers and original bronze attributes in a pinned read.

    Normalization omits raw attributes. Every cache lookup hashes fresh bronze
    bytes; parsing on a miss uses those same bytes. Only 32 Boolean results are
    retained. Larger sources use uncached streaming rather than unbounded RAM.
    This label is not an integrity check or proof of authentic provider origin.
    """
    if any(_explicit_synthetic(row) for row in normalized_events):
        return True
    path = pinned_path(lake / "bronze/raw_events.jsonl").resolve()
    try:
        with path.open("rb") as stream:
            raw = stream.read(_MAX_SOURCE_BYTES + 1)
    except FileNotFoundError:
        return False
    if len(raw) > _MAX_SOURCE_BYTES:
        del raw
        return _bronze_rows_contain_synthetic(iter_jsonl(path))
    key = (str(path), hashlib.sha256(raw).digest())
    with _cache_lock:
        if key in _cache:
            _cache.move_to_end(key)
            return _cache[key]

    def rows() -> Iterable[dict[str, Any]]:
        for line in raw.splitlines():
            if line.strip():
                row = strict_json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError("bronze provenance requires JSON objects")
                yield row

    result = _bronze_rows_contain_synthetic(rows())
    with _cache_lock:
        for previous in tuple(_cache):
            if previous[0] == key[0]:
                del _cache[previous]
        _cache[key] = result
        while len(_cache) > _MAX_CACHE_ENTRIES:
            _cache.popitem(last=False)
    return result
