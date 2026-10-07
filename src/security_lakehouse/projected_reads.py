"""Bounded compact projections, keyed by freshly read JSONL bytes.

This avoids repeatedly decoding large unused attributes in display reads. It is
not a source authenticity check: callers retain their existing integrity policy.
Every call reads the current source bytes; no stat-only trust or mutable result
is cached. Strict validation still covers unselected fields on a cache miss.
"""

from __future__ import annotations

import hashlib
import json
import threading
import weakref
from collections import OrderedDict
from pathlib import Path
from typing import Any

from security_lakehouse import strict_json
from security_lakehouse.generations import pinned_path
from security_lakehouse.io import iter_jsonl, resolve_path

MAX_CACHE_BYTES = 32 * 1024 * 1024
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_CACHE_ENTRIES = 32
_cache: OrderedDict[tuple[str, tuple[str, ...] | None, bytes], bytes] = OrderedDict()
_cache_lock = threading.Lock()
_build_locks: weakref.WeakValueDictionary = weakref.WeakValueDictionary()


def _trim_cache() -> None:
    while _cache and (len(_cache) > MAX_CACHE_ENTRIES or sum(map(len, _cache.values())) > MAX_CACHE_BYTES):
        _cache.popitem(last=False)


def read_projection(
    path: str | Path,
    fields: tuple[str, ...] | None,
    *,
    missing_ok: bool = False,
    base_dir: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Read selected fields, or complete rows when ``fields`` is None.

    The cache holds at most 32 MiB of serialized projections and 32 entries.
    Source reads are capped at 128 MiB; larger files use uncached streaming.
    Returned objects are decoded anew so one consumer cannot alter another's.
    """
    target = resolve_path(pinned_path(Path(path)), base_dir=base_dir)
    with _cache_lock:
        _trim_cache()
    try:
        with target.open("rb") as stream:
            raw = stream.read(MAX_SOURCE_BYTES + 1)
    except FileNotFoundError:
        if missing_ok:
            return []
        raise
    if len(raw) > MAX_SOURCE_BYTES:
        del raw
        return [
            row if fields is None else {key: row[key] for key in fields if key in row}
            for row in iter_jsonl(target, base_dir=base_dir)
        ]
    cache_key = (str(target), fields, hashlib.sha256(raw).digest())
    with _cache_lock:
        cached = _cache.get(cache_key)
        if cached is not None:
            _cache.move_to_end(cache_key)
    if cached is not None:
        return json.loads(cached)
    with _cache_lock:
        build_lock = _build_locks.setdefault(cache_key, threading.Lock())
    with build_lock:
        # Another reader may have completed this exact projection while this
        # reader waited. Different paths and byte identities never share a lock.
        with _cache_lock:
            cached = _cache.get(cache_key)
            if cached is not None:
                _cache.move_to_end(cache_key)
        if cached is not None:
            return json.loads(cached)
        rows = []
        for line_number, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue
            row = strict_json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"{target}:{line_number}: expected JSON object")
            rows.append(row if fields is None else {key: row[key] for key in fields if key in row})
        del raw
        encoded = json.dumps(rows, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) <= MAX_CACHE_BYTES:
            with _cache_lock:
                # Keep only the current byte identity per path and field selection.
                for previous in tuple(_cache):
                    if previous[:2] == cache_key[:2]:
                        del _cache[previous]
                _cache[cache_key] = encoded
                _trim_cache()
        return rows
