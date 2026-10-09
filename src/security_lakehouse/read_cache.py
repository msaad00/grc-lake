"""Bounded, tenant-scoped memo for read models derived from lake artifacts.

An entry belongs to one resolved lake root and one caller-chosen slot, and
records the version of every input file it was built from (see
:func:`security_lakehouse.io.file_version`). Each lookup recomputes those
versions, one ``stat`` per settled file, and rebuilds on any difference, so a
new generation, a rewritten legacy artifact, or a pruned file is never served
from an older entry. Callers must treat returned values as read-only and copy
whatever they hand out.

Only the newest version of a root and slot is kept, a root holds at most
``per_root`` entries, and the cache holds at most ``max_entries``. Concurrent
misses for the same root and slot build once; other roots never wait on them.
"""

from __future__ import annotations

import threading
import weakref
from collections import OrderedDict
from collections.abc import Callable, Hashable, Iterable
from pathlib import Path
from typing import Any, Generic, TypeVar

from security_lakehouse.io import FileVersion, file_version, resolve_path

T = TypeVar("T")


def lake_root(lake: str | Path) -> str:
    return str(resolve_path(lake))


def input_versions(lake: str | Path, relative_paths: Iterable[str]) -> tuple[tuple[str, FileVersion | None], ...]:
    """Versions of the pinned lake artifacts a read model is derived from."""
    root = Path(lake)
    return tuple(file_version(root / relative, base_dir=root) for relative in relative_paths)


class DerivedCache(Generic[T]):
    def __init__(self, *, max_entries: int, per_root: int = 4) -> None:
        self.max_entries = max_entries
        self.per_root = per_root
        self._entries: OrderedDict[tuple[str, Hashable], tuple[Hashable, T]] = OrderedDict()
        self._lock = threading.Lock()
        self._build_locks: weakref.WeakValueDictionary[Any, Any] = weakref.WeakValueDictionary()

    def get(
        self,
        lake: str | Path,
        slot: Hashable,
        version: Hashable,
        build: Callable[[], T],
        *,
        accept: Callable[[T], bool] | None = None,
    ) -> T:
        """Return the entry for ``(lake, slot)`` built from ``version``, building it on a miss.

        ``accept`` can reject a version-matched entry (for example one whose
        validity window has passed); a rejected entry is rebuilt.
        """
        key = (lake_root(lake), slot)
        cached = self._lookup(key, version, accept)
        if cached is not None:
            return cached[0]
        with self._lock:
            build_lock = self._build_locks.get(key)
            if build_lock is None:
                build_lock = threading.Lock()
                self._build_locks[key] = build_lock
        with build_lock:
            cached = self._lookup(key, version, accept)
            if cached is not None:
                return cached[0]
            value = build()
            with self._lock:
                self._entries[key] = (version, value)
                self._entries.move_to_end(key)
                same_root = [entry for entry in self._entries if entry[0] == key[0]]
                for stale in same_root[: max(0, len(same_root) - self.per_root)]:
                    del self._entries[stale]
                while len(self._entries) > self.max_entries:
                    self._entries.popitem(last=False)
            return value

    def _lookup(
        self, key: tuple[str, Hashable], version: Hashable, accept: Callable[[T], bool] | None
    ) -> tuple[T] | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or entry[0] != version or (accept is not None and not accept(entry[1])):
                return None
            self._entries.move_to_end(key)
            return (entry[1],)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


def json_copy(value: Any) -> Any:
    """Copy a JSON-shaped value so a consumer cannot alter a cached original."""
    if isinstance(value, dict):
        return {key: json_copy(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_copy(item) for item in value]
    return value


def rows_are_flat(rows: Iterable[dict[str, Any]]) -> bool:
    """True when no row holds a nested object or list, so a shallow row copy is a full copy."""
    return not any(isinstance(item, dict | list) for row in rows for item in row.values())


def copy_rows(rows: Iterable[dict[str, Any]], *, flat: bool = False) -> list[dict[str, Any]]:
    """Copy rows; pass ``flat`` only for rows checked with :func:`rows_are_flat`."""
    if flat:
        return [row.copy() for row in rows]
    return [json_copy(row) for row in rows]
