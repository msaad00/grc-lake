"""Explicit, recoverable archival of unreferenced evidence generations."""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import time
from pathlib import Path
from typing import Any

from security_lakehouse.generations import active_generation, publication_lock, verify_generation
from security_lakehouse.io import read_json


def _references(value: Any) -> set[str]:
    if isinstance(value, dict):
        own = {value["generation_id"]} if isinstance(value.get("generation_id"), str) else set()
        return own.union(*(_references(v) for v in value.values()))
    if isinstance(value, list):
        return set().union(*(_references(v) for v in value))
    return set()


def retained_generations(lake: Path) -> set[str]:
    from security_lakehouse.assessment import verify_snapshot_chain

    if not verify_snapshot_chain(lake)["ok"]:
        raise ValueError("snapshot history must verify before retention changes")
    protected = set()
    for path in (lake / "gold/snapshots").glob("*.json"):
        protected.update(_references(read_json(path)))
    root = lake.parent.parent if lake.parent.name == "tenants" else lake
    if (root / "server/app.db").is_file() or os.environ.get("TRUSTOPS_DATABASE_URL"):
        from sqlalchemy import select

        from security_lakehouse.db.base import create_engine_for, session_factory
        from security_lakehouse.db.models import AuditWorkpaper, RemediationTask

        engine = create_engine_for(root)
        try:
            with session_factory(engine)() as session:
                for column in (AuditWorkpaper.content_json, RemediationTask.verification_history):
                    for value in session.scalars(select(column)):
                        protected.update(_references(json.loads(value)))
        finally:
            engine.dispose()
    return protected


def archive_generations(
    lake: Path, *, older_than_days: int = 90, keep_latest: int = 3, archive_to: Path | None = None
) -> dict[str, Any]:
    """Report by default; when requested, copy, verify, fsync, then remove old copies.

    Active readers and retained snapshot/workpaper/receipt references are protected.
    External references cannot be discovered: select a retention window covering
    the evidence period and retain the verified archive for external consumers.
    """
    lake = lake.resolve()
    if not lake.is_dir() or older_than_days < 1 or keep_latest < 1:
        raise ValueError("retention requires an existing lake, at least one day and one retained generation")
    if archive_to is not None:
        archive_to = archive_to.resolve()
        if archive_to == lake or lake in archive_to.parents:
            raise ValueError("archive destination must be outside the lake")
    with publication_lock(lake):
        parent = lake / "generations"
        paths = (
            sorted(
                (p for p in parent.iterdir() if p.is_dir() and not p.is_symlink()),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if parent.is_dir()
            else []
        )
        active = active_generation(lake)
        protected = retained_generations(lake) | {p.name for p in paths[:keep_latest]}
        if active:
            protected.add(active.name)
        cutoff = time.time() - older_than_days * 86400
        if any(p.is_symlink() for directory in paths for p in directory.rglob("*")):
            raise ValueError("generation contains a symlink; retention requires regular artifacts")
        report: dict[str, Any] = {
            "generation_count": len(paths),
            "total_bytes": sum(p.stat().st_size for directory in paths for p in directory.rglob("*") if p.is_file()),
            "candidates": [],
            "archived": [],
        }
        for path in paths:
            if path.name in protected or path.stat().st_mtime >= cutoff:
                continue
            handle = os.open(path, os.O_RDONLY)
            try:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                if path.name in retained_generations(lake):
                    continue
                verify_generation(path)
                report["candidates"].append(path.name)
                if archive_to is None:
                    continue
                destination = archive_to / path.name
                if destination.exists():
                    raise ValueError("archive destination already contains this generation; reconcile before retry")
                shutil.copytree(path, destination, symlinks=True)
                verify_generation(destination)
                for copied in destination.rglob("*"):
                    if copied.is_file():
                        with copied.open("rb") as stream:
                            os.fsync(stream.fileno())
                for directory in [
                    *reversed([p for p in destination.rglob("*") if p.is_dir()]),
                    destination,
                    archive_to,
                ]:
                    fd = os.open(directory, os.O_RDONLY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                shutil.rmtree(path)
                fd = os.open(parent, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
                report["archived"].append(path.name)
            finally:
                os.close(handle)
        return report
