"""Verified assessment generations and POSIX atomic publication.

Only materialized artifacts belong to a generation. Connector configuration,
raw intake, run ledgers, assignments, and review history remain at the lake root.
"""

from __future__ import annotations

import contextlib
import fcntl
import inspect
import json
import os
import shutil
from collections.abc import Mapping
from contextvars import ContextVar
from functools import wraps
from pathlib import Path
from types import MappingProxyType
from uuid import uuid4

from security_lakehouse.io import file_sha256

ARTIFACTS = (
    "catalog/control_map.json",
    "catalog/bundle.json",
    "catalog/safeguards.json",
    "manifest.json",
    "bronze/raw_events.jsonl",
    "silver/normalized_events.jsonl",
    "gold/control_posture.jsonl",
    "gold/control_tests.jsonl",
    "gold/ccf_assessment.json",
    "gold/evidence_freshness.jsonl",
    "gold/asset_risk.jsonl",
    "gold/metrics.json",
    "gold/dashboard_data.json",
    "gold/evidence_integrity.json",
    "gold/current_posture.json",
    "mart/security_lakehouse.sqlite",
    "mart/security_data_lake.duckdb",
)
_POINTER = ".active-generation"
_pinned: ContextVar[Mapping[Path, Path | None]] = ContextVar("assessment_generations", default=MappingProxyType({}))
_writers: ContextVar[frozenset[Path]] = ContextVar("generation_writers", default=frozenset())


def active_generation(lake: str | Path) -> Path | None:
    root = Path(lake).resolve()
    pointer = root / _POINTER
    if not pointer.is_symlink():
        if pointer.exists():
            raise ValueError("active generation pointer must be a symlink")
        return None
    target = pointer.resolve(strict=True)
    if target.parent != root / "generations" or not (target / "generation.json").is_file():
        raise ValueError("invalid assessment generation pointer")
    return target


@contextlib.contextmanager
def publication_lock(lake: str | Path):
    root = Path(lake).resolve()
    if root in _writers.get():
        yield
        return
    if root in _pinned.get() and _pinned.get()[root] is None:
        raise ValueError("cannot publish within a pinned legacy read")
    root.mkdir(parents=True, exist_ok=True)
    lock = os.open(root, os.O_RDONLY)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        token = _writers.set(_writers.get() | {root})
        try:
            yield
        finally:
            _writers.reset(token)
            fcntl.flock(lock, fcntl.LOCK_UN)
    finally:
        os.close(lock)


def serialized_publication(func):
    @wraps(func)
    def wrapped(raw_path, out_dir, *args, **kwargs):
        with publication_lock(out_dir):
            parent = Path(out_dir).resolve() / "generations"
            before = set(parent.iterdir()) if parent.is_dir() else set()
            try:
                return func(raw_path, out_dir, *args, **kwargs)
            except BaseException:
                active = active_generation(out_dir)
                for candidate in set(parent.iterdir()) - before if parent.is_dir() else set():
                    if candidate != active and candidate.is_dir() and not candidate.is_symlink():
                        shutil.rmtree(candidate)
                raise

    return wrapped


@contextlib.contextmanager
def pin_generation(lake: str | Path):
    root = Path(lake).resolve()
    if root in _pinned.get():
        yield _pinned.get()[root]
        return
    lock = None
    generation_lock = None
    try:
        while True:
            generation = active_generation(root)
            if generation is None:
                # Only legacy readers block publication. An existing generation
                # stays readable while a new one is built under the writer lock.
                if root.exists() and root not in _writers.get() and not (root / "generation.json").is_file():
                    lock = os.open(root, os.O_RDONLY)
                    fcntl.flock(lock, fcntl.LOCK_SH)
                    generation = active_generation(root)
                if generation is None:
                    break
            try:
                generation_lock = os.open(generation, os.O_RDONLY)
            except FileNotFoundError:
                continue  # Retention won the race before the read lease.
            fcntl.flock(generation_lock, fcntl.LOCK_SH)
            if generation.is_dir():
                if lock is not None:
                    os.close(lock)
                    lock = None
                break
            os.close(generation_lock)
            generation_lock = None

        token = _pinned.set({**_pinned.get(), root: generation})
        try:
            yield generation
        finally:
            _pinned.reset(token)
    finally:
        if generation_lock is not None:
            os.close(generation_lock)
        if lock is not None:
            os.close(lock)


def generation_reader(func):
    """Pin generated IO for one public read/export, retaining operational paths."""
    signature = inspect.signature(func)

    @wraps(func)
    def wrapped(*args, **kwargs):
        arguments = signature.bind(*args, **kwargs).arguments
        lake = arguments.get("lake_dir", arguments.get("lake"))
        if lake is None:
            raise TypeError("generation reader requires lake_dir or lake")
        with pin_generation(lake):
            return func(*args, **kwargs)

    return wrapped


def pinned_path(path: Path) -> Path:
    """Redirect only known assessment files within an explicitly pinned read."""
    absolute = Path(os.path.abspath(path.expanduser()))
    for root, generation in _pinned.get().items():
        # Resolve parents of the lake, but not artifact symlinks through current.
        for relative in ARTIFACTS:
            suffix = Path(relative)
            if absolute.parts[-len(suffix.parts) :] != suffix.parts:
                continue
            candidate_root = absolute.parents[len(suffix.parts) - 1].resolve()
            if candidate_root == root and generation is not None:
                return generation / relative
    return path


def generation_identity(lake: str | Path) -> dict | None:
    root = Path(lake).resolve()
    generation = _pinned.get().get(root) if root in _pinned.get() else active_generation(root)
    if generation is None and (root / "generation.json").is_file():
        generation = root
    if generation is None:
        return None
    return {"generation_id": generation.name, "manifest_sha256": file_sha256(generation / "generation.json")}


def new_generation(lake: Path) -> Path:
    root = lake.resolve()
    parent = root / "generations"
    if parent.resolve() != parent:
        raise ValueError("generation directory must remain inside the lake")
    path = parent / uuid4().hex
    path.mkdir(parents=True)
    return path


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def seal_generation(generation: Path, *, legacy: bool = False) -> None:
    from security_lakehouse.io import write_json

    hashes = {}
    for relative in ARTIFACTS:
        path = generation / relative
        if path.is_file():
            hashes[relative] = file_sha256(path)
            with path.open("rb") as stream:
                os.fsync(stream.fileno())
    write_json(
        generation / "generation.json",
        {
            "schema_version": "trustops.generation.v2",
            "ccf_projection_version": None if legacy else 1,
            "legacy": legacy,
            "generation_id": generation.name,
            "artifacts": hashes,
        },
    )
    verify_generation(generation)
    for directory in sorted(p for p in generation.iterdir() if p.is_dir()):
        _fsync_dir(directory)
    _fsync_dir(generation)
    _fsync_dir(generation.parent)


def verify_generation(generation: Path) -> None:
    manifest = json.loads((generation / "generation.json").read_text())
    fields = {"schema_version", "generation_id", "legacy", "artifacts"}
    if isinstance(manifest, dict) and manifest.get("schema_version") == "trustops.generation.v2":
        fields.add("ccf_projection_version")
    if (
        not isinstance(manifest, dict)
        or set(manifest) != fields
        or manifest.get("schema_version") not in {"trustops.generation.v1", "trustops.generation.v2"}
        or type(manifest.get("legacy")) is not bool
        or not isinstance(manifest.get("artifacts"), dict)
        or manifest.get("generation_id") != generation.name
        or not manifest.get("artifacts")
        or (
            manifest.get("schema_version") == "trustops.generation.v2"
            and manifest.get("ccf_projection_version") != (None if manifest["legacy"] else 1)
        )
    ):
        raise ValueError("invalid generation manifest")
    required = set(ARTIFACTS) - {"mart/security_data_lake.duckdb"}
    if manifest.get("schema_version") == "trustops.generation.v1":
        required -= {"catalog/safeguards.json", "gold/ccf_assessment.json"}
    if not manifest.get("legacy", False) and not required <= set(manifest["artifacts"]):
        raise ValueError("generation is missing required assessment artifacts")
    for relative, expected in manifest["artifacts"].items():
        if relative not in ARTIFACTS:
            raise ValueError("unknown generation artifact")
        path = generation / relative
        if path.resolve().parent != (generation / relative).parent or not path.is_file():
            raise ValueError("invalid generation artifact path")
        if file_sha256(path) != expected:
            raise ValueError(f"generation artifact hash mismatch: {relative}")


def _switch_pointer(lake: Path, generation: Path) -> None:
    temporary = lake / f".generation-pointer-{uuid4().hex}"
    try:
        temporary.symlink_to(generation.relative_to(lake))
        os.replace(temporary, lake / _POINTER)
        _fsync_dir(lake)
    finally:
        temporary.unlink(missing_ok=True)


def publish_generation(lake: Path, generation: Path) -> None:
    """Migrate aliases without changing the old view, then switch one pointer."""
    lake = lake.resolve()
    verify_generation(generation)
    if active_generation(lake) is None:
        existing = [relative for relative in ARTIFACTS if (lake / relative).is_file()]
        if existing:
            baseline = new_generation(lake)
            for relative in existing:
                destination = baseline / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(lake / relative, destination)
            seal_generation(baseline, legacy=True)
            _switch_pointer(lake, baseline)
    for relative in ARTIFACTS:
        alias = lake / relative
        if alias.parent.resolve() != alias.parent:
            raise ValueError("artifact directory must remain inside the lake")
        alias.parent.mkdir(parents=True, exist_ok=True)
        target = Path(os.path.relpath(lake / _POINTER / relative, alias.parent))
        if alias.is_symlink() and alias.readlink() == target:
            continue
        temporary = alias.with_name(f".{alias.name}-{uuid4().hex}")
        try:
            temporary.symlink_to(target)
            os.replace(temporary, alias)
            _fsync_dir(alias.parent)
        finally:
            temporary.unlink(missing_ok=True)
    _switch_pointer(lake, generation)


def assert_mutable(path: Path) -> None:
    """Published assessment artifacts can only be replaced by a new generation."""
    for parent in (path.parent, path.parent.parent):
        if parent.parent.name == "generations" and (parent / "generation.json").is_file():
            raise ValueError("published assessment generation is immutable; run the pipeline to replace it")
