"""File IO helpers for JSON and JSONL lake artifacts."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
import threading
import time
from collections import Counter, OrderedDict
from collections.abc import Callable, Generator, Iterable, Iterator
from itertools import islice
from pathlib import Path
from typing import Any, TypeVar

from security_lakehouse import strict_json


def canonical_sha256(payload: Any) -> str:
    """Hash the stable JSON representation shared by writers and verifiers."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def file_sha256(path: str | Path) -> str:
    """Hash file bytes with a reusable 1 MiB buffer; propagate read failures.

    Callers supply an already scoped/pinned path. This helper does not resolve
    paths or change generation selection, and does not snapshot mutable files.
    """
    digest = hashlib.sha256()
    buffer = bytearray(1024 * 1024)
    view = memoryview(buffer)
    with Path(path).open("rb") as stream:
        while count := stream.readinto(buffer):
            digest.update(view[:count])
    return digest.hexdigest()


def resolve_path(path: str | Path, *, base_dir: str | Path | None = None) -> Path:
    """Return a canonical local path, optionally confined under ``base_dir``.

    Server-mode callers should pass the tenant/lake root as ``base_dir`` before
    reading or writing lake artifacts. That makes the path policy explicit at
    the shared IO boundary and prevents traversal through ``..`` components or
    existing symlink parents. CLI callers can omit ``base_dir`` to keep normal
    local file paths working.
    """
    raw = os.fspath(path)
    if "\x00" in raw:
        raise ValueError("path contains NUL byte")
    # Canonicalization is the guard boundary: server callers pass ``base_dir``
    # below, and the real target must stay under that trusted root before any
    # read/write operation occurs.
    target = Path(os.path.realpath(os.path.abspath(os.path.expanduser(raw))))
    if base_dir is None:
        return target
    root_raw = os.fspath(base_dir)
    if "\x00" in root_raw:
        raise ValueError("base_dir contains NUL byte")
    root = Path(os.path.realpath(os.path.abspath(os.path.expanduser(root_raw))))
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ValueError("path is outside allowed root") from exc
    return target


def _iter_jsonl_lines(
    path: str | Path,
    *,
    missing_ok: bool = False,
    base_dir: str | Path | None = None,
) -> Generator[tuple[int, str], None, None]:
    """Yield ``(line_no, stripped_line)`` from a JSONL file without loading it whole."""
    from security_lakehouse.generations import pinned_path

    target = resolve_path(pinned_path(Path(path)), base_dir=base_dir)
    # lgtm[py/path-injection]
    if missing_ok and not target.exists():
        return
    # lgtm[py/path-injection]
    with target.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            stripped = line.strip()
            if stripped:
                yield line_no, stripped


def _parse_jsonl_line(path: str | Path, line_no: int, stripped: str) -> dict[str, Any]:
    try:
        item = strict_json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
    if not isinstance(item, dict):
        raise ValueError(f"{path}:{line_no}: expected JSON object")
    return item


def iter_jsonl(
    path: str | Path,
    *,
    missing_ok: bool = False,
    base_dir: str | Path | None = None,
) -> Iterator[dict[str, Any]]:
    """Stream JSON objects from a JSONL file one row at a time."""
    for line_no, stripped in _iter_jsonl_lines(path, missing_ok=missing_ok, base_dir=base_dir):
        yield _parse_jsonl_line(path, line_no, stripped)


def iter_jsonl_slice(
    path: str | Path,
    start: int,
    stop: int,
    *,
    missing_ok: bool = False,
    base_dir: str | Path | None = None,
) -> Iterator[dict[str, Any]]:
    """Stream rows ``[start, stop)`` of a JSONL file.

    Rows before ``start`` are skipped without being parsed, and the file is not
    read past row ``stop``. Row numbers count non-empty lines, matching
    :func:`count_jsonl`.
    """
    with contextlib.closing(_iter_jsonl_lines(path, missing_ok=missing_ok, base_dir=base_dir)) as lines:
        for line_no, stripped in islice(lines, start, stop):
            yield _parse_jsonl_line(path, line_no, stripped)


def read_jsonl(
    path: str | Path,
    *,
    missing_ok: bool = False,
    base_dir: str | Path | None = None,
) -> list[dict[str, Any]]:
    return list(iter_jsonl(path, missing_ok=missing_ok, base_dir=base_dir))


def count_jsonl(
    path: str | Path,
    *,
    missing_ok: bool = False,
    base_dir: str | Path | None = None,
) -> int:
    """Count non-empty JSONL rows without parsing each object."""
    return sum(1 for _line_no, _line in _iter_jsonl_lines(path, missing_ok=missing_ok, base_dir=base_dir))


_VALIDATED_COUNTS: OrderedDict[tuple[str, tuple[int, ...] | bytes], int] = OrderedDict()
_VALIDATED_COUNTS_LOCK = threading.Lock()
_VALIDATED_COUNTS_MAX = 256
# Timestamps can be as coarse as a scheduler tick (or 2 s on some network and
# FAT mounts), so a write in the same tick as an earlier one may leave
# mtime/ctime unchanged. Only files whose timestamps are older than this are
# trusted by stat alone.
_RACY_TIMESTAMP_WINDOW_NS = 2 * 10**9


def _stat_version(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def validated_jsonl_count(
    path: str | Path,
    *,
    missing_ok: bool = False,
    base_dir: str | Path | None = None,
) -> int:
    """Count rows after checking that every row parses, without keeping any.

    The full parse runs once per file version, so a paged reader can stay
    fail-closed on rows outside its page while parsing only the rows it
    serves. Raises ``ValueError`` on the first invalid row.

    A settled file (mtime and ctime older than two seconds) is identified by
    device, inode, size, mtime, and ctime, so an unchanged file costs one
    ``stat``. POSIX ctime cannot be set from user space, so an in-place
    same-size rewrite that restores mtime (``cp -p``, ``touch -d``) still
    changes the key. A file changed within the window is re-read and keyed by
    the SHA-256 of its bytes, which covers writes in the same timestamp tick.
    The remaining gap is a filesystem without a real change time (on Windows
    ``st_ctime`` is creation time), or a wall-clock step backwards of more
    than the window between two writes.
    """
    from security_lakehouse.generations import pinned_path

    target = resolve_path(pinned_path(Path(path)), base_dir=base_dir)
    try:
        before = target.stat()
    except FileNotFoundError:
        if missing_ok:
            return 0
        raise
    newest_change = max(before.st_mtime_ns, before.st_ctime_ns)
    settled = time.time_ns() - newest_change > _RACY_TIMESTAMP_WINDOW_NS
    version: tuple[int, ...] | bytes
    if settled:
        version = _stat_version(before)
    else:
        digest = hashlib.sha256()
        try:
            with target.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        except FileNotFoundError:
            if missing_ok:
                return 0
            raise
        version = digest.digest()
    key = (str(target), version)
    with _VALIDATED_COUNTS_LOCK:
        cached = _VALIDATED_COUNTS.get(key)
        if cached is not None:
            _VALIDATED_COUNTS.move_to_end(key)
            return cached
    count = 0
    for line_no, stripped in _iter_jsonl_lines(path, base_dir=base_dir):
        _parse_jsonl_line(path, line_no, stripped)
        count += 1
    try:
        after = target.stat()
    except FileNotFoundError:
        return count
    if _stat_version(after) != _stat_version(before):
        # Changed while being read: the count belongs to unknown bytes.
        return count
    with _VALIDATED_COUNTS_LOCK:
        for previous in [k for k in _VALIDATED_COUNTS if k[0] == key[0]]:
            del _VALIDATED_COUNTS[previous]
        _VALIDATED_COUNTS[key] = count
        while len(_VALIDATED_COUNTS) > _VALIDATED_COUNTS_MAX:
            _VALIDATED_COUNTS.popitem(last=False)
    return count


T = TypeVar("T")


def jsonl_field_counts(
    path: str | Path,
    field: str,
    *,
    missing_ok: bool = False,
    base_dir: str | Path | None = None,
    default: str = "unknown",
) -> Counter[str]:
    """Count occurrences of ``row[field]`` while streaming a JSONL file."""
    counts: Counter[str] = Counter()
    for row in iter_jsonl(path, missing_ok=missing_ok, base_dir=base_dir):
        counts[str(row.get(field) or default)] += 1
    return counts


def iter_jsonl_batches(
    path: str | Path,
    batch_size: int,
    *,
    missing_ok: bool = False,
    base_dir: str | Path | None = None,
) -> Iterator[list[dict[str, Any]]]:
    """Yield fixed-size batches from a JSONL file for chunked processing."""
    if batch_size < 1:
        raise ValueError("batch_size must be >= 1")
    batch: list[dict[str, Any]] = []
    for row in iter_jsonl(path, missing_ok=missing_ok, base_dir=base_dir):
        batch.append(row)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def write_jsonl_from_iterable(
    path: str | Path,
    rows: Iterable[dict[str, Any]],
    *,
    base_dir: str | Path | None = None,
    on_progress: Callable[[int], None] | None = None,
) -> int:
    """Write rows from a generator/iterator; returns rows written."""
    output = resolve_path(path, base_dir=base_dir)
    written = 0

    def _chunks() -> Iterator[str]:
        nonlocal written
        for row in rows:
            written += 1
            if on_progress is not None:
                on_progress(written)
            yield strict_json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"

    _atomic_write(output, _chunks())
    return written


def _atomic_write(output: Path, text_chunks: Iterable[str]) -> None:
    """Write ``text_chunks`` to ``output`` atomically.

    The payload is streamed into a temporary file in the same directory as the
    destination, flushed and fsync'd, then moved into place with
    :func:`os.replace`, which is atomic on POSIX for same-filesystem renames. A
    reader therefore only ever sees the previous complete file or the new
    complete file, never a half-written/truncated one. On any error the temp
    file is removed and the exception re-raised, so a failed write never
    replaces the existing destination.
    """
    from security_lakehouse.generations import assert_mutable

    assert_mutable(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=output.parent, prefix=output.name + ".", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for chunk in text_chunks:
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, output)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_path)
        raise


def write_jsonl(
    path: str | Path,
    rows: Iterable[dict[str, Any]],
    *,
    base_dir: str | Path | None = None,
) -> None:
    output = resolve_path(path, base_dir=base_dir)
    _atomic_write(
        output,
        (strict_json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
    )


def append_jsonl(
    path: str | Path,
    row: dict[str, Any],
    *,
    base_dir: str | Path | None = None,
) -> None:
    """Append one JSON object as a line, durably.

    Used for append-only ledgers: the line is flushed and fsync'd before the
    call returns so a crash cannot lose an acknowledged record. Unlike
    :func:`write_jsonl` this never rewrites existing content.
    """
    from security_lakehouse.generations import assert_mutable

    output = resolve_path(path, base_dir=base_dir)
    assert_mutable(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    line = strict_json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
    with output.open("a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())


def write_json(path: str | Path, payload: Any, *, base_dir: str | Path | None = None) -> None:
    output = resolve_path(path, base_dir=base_dir)
    _atomic_write(output, [strict_json.dumps(payload, indent=2, sort_keys=True) + "\n"])


def read_json(path: str | Path, *, base_dir: str | Path | None = None) -> Any:
    from security_lakehouse.generations import pinned_path

    return strict_json.loads(resolve_path(pinned_path(Path(path)), base_dir=base_dir).read_text(encoding="utf-8"))
