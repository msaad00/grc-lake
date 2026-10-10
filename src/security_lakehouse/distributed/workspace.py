"""Private writes become visible only with a database-fenced atomic publication."""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from security_lakehouse.distributed.catalog import Catalog, Conflict
from security_lakehouse.distributed.context import WorkspaceBinding, binding
from security_lakehouse.distributed.objects import ObjectStore
from security_lakehouse.ledger import chain_lock

_log = logging.getLogger(__name__)
LEASE_SECONDS = 90
HEARTBEAT_SECONDS: float = 10
HEARTBEAT_RETRY_SECONDS: float = 1


class Runtime:
    def __init__(self, catalog: Catalog, objects: ObjectStore, scratch: Path):
        self.catalog = catalog
        self.objects = objects
        self.scratch = scratch.resolve()
        self.scratch.mkdir(parents=True, exist_ok=True, mode=0o700)

    def read_path(self, tenant_id: str, *, version: int | None = None) -> Path:
        """Internal cache access; callers needing a stable lifetime use read()."""
        with chain_lock(self.scratch / "cache"):
            return self._read_path(tenant_id, version=version)

    def _read_path(self, tenant_id: str, *, version: int | None = None) -> Path:
        head = self.catalog.head(tenant_id) if version is None else self.catalog.revision(tenant_id, version)
        digest = hashlib.sha256(json.dumps(head.manifest, sort_keys=True).encode()).hexdigest()
        parent = self.scratch / "read-cache" / tenant_id
        target = parent / f"{head.version}-{digest}"
        if (target / ".distributed-ready").exists():
            (target / ".distributed-ready").touch()
            return target
        # Keep one revision per tenant, within replica-wide entry/byte bounds.
        # Readers copy under this same process-shared lock, so eviction never
        # removes an in-use private view. Marker mtimes track cross-process LRU.
        cache = self.scratch / "read-cache"
        if parent.exists():
            shutil.rmtree(parent)
        needed = sum(entry["size"] for entry in head.manifest.get("files", {}).values())
        if needed > self.catalog.config.read_cache_limit:
            raise ValueError("tenant revision exceeds read cache byte limit")
        # A killed downloader may leave an incomplete directory; no other
        # materialization runs while this lock is held. Reclaim it on a miss.
        for candidate in cache.glob("*/*"):
            if candidate.is_dir() and not (candidate / ".distributed-ready").exists():
                shutil.rmtree(candidate)
        entries = []
        for marker in cache.glob("*/*/.distributed-ready"):
            size = sum(p.stat().st_size for p in marker.parent.rglob("*") if p.is_file() and not p.is_symlink())
            entries.append((marker.stat().st_mtime_ns, marker.parent.parent, size))
        entries.sort()
        retained = sum(entry[2] for entry in entries)
        while entries and (
            len(entries) >= self.catalog.config.read_cache_entries
            or retained + needed > self.catalog.config.read_cache_limit
            or shutil.disk_usage(self.scratch).free < needed + 256 * 1024**2
        ):
            _, stale, size = entries.pop(0)
            shutil.rmtree(stale)
            retained -= size
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = Path(tempfile.mkdtemp(prefix="download-", dir=parent))
        try:
            self._headroom(head.manifest)
            self.objects.restore(tenant_id, head.manifest, temporary)
            (temporary / ".distributed-ready").touch()
            temporary.rename(target)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
        return target

    @contextmanager
    def read_transaction(self, tenant_id: str):
        # Compatibility readers may create locks or projections. Their local
        # writes must never poison the immutable revision cache or other readers.
        with tempfile.TemporaryDirectory(prefix="reader-", dir=self.scratch) as folder:
            private = Path(folder) / "lake"
            with chain_lock(self.scratch / "cache"):
                path = self._read_path(tenant_id)
                needed = sum(p.stat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink())
                if shutil.disk_usage(self.scratch).free < needed + 256 * 1024**2:
                    raise OSError("insufficient scratch space for private reader")
                shutil.copytree(path, private, symlinks=True)
            yield WorkspaceBinding(tenant_id, private)

    def _headroom(self, manifest):
        needed = sum(entry["size"] for entry in manifest.get("files", {}).values())
        if shutil.disk_usage(self.scratch).free < needed + 256 * 1024**2:
            raise OSError("insufficient scratch space to materialize tenant revision")

    @contextmanager
    def read(self, tenant_id: str):
        with self.read_transaction(tenant_id) as workspace:
            token = binding.set(workspace)
            try:
                yield workspace.path
            finally:
                binding.reset(token)

    @contextmanager
    def transaction(self, tenant_id: str, *, wait_seconds: float = 0):
        if binding.get() is not None:
            raise RuntimeError("distributed tenant writes cannot be nested")
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                acquired_at = time.monotonic()
                lease = self.catalog.acquire(tenant_id, owner=uuid.uuid4().hex, seconds=LEASE_SECONDS)
                break
            except Conflict:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(min(0.1, max(0, deadline - time.monotonic())))
        stop = threading.Event()
        lost = threading.Event()

        def renew():
            # The lease runs at least LEASE_SECONDS from the last confirmed
            # renewal, so a failed heartbeat is retried until that window
            # closes. Retrying never authorizes work: publication still
            # requires the database to confirm the unexpired fence.
            confirmed = acquired_at
            interval = HEARTBEAT_SECONDS
            while not stop.wait(interval):
                attempted = time.monotonic()
                try:
                    renewed = self.catalog.renew(lease, seconds=LEASE_SECONDS)
                except Exception as exc:  # noqa: BLE001 - fail closed at a distributed ownership boundary
                    if time.monotonic() - confirmed >= LEASE_SECONDS:
                        lost.set()
                        return
                    _log.warning("writer lease renewal failed (%s); retrying", type(exc).__name__)
                    interval = HEARTBEAT_RETRY_SECONDS
                    continue
                if not renewed:
                    lost.set()
                    return
                confirmed = attempted
                interval = HEARTBEAT_SECONDS

        heartbeat = threading.Thread(target=renew, name="grc-lake-writer-lease", daemon=True)
        heartbeat.start()
        try:
            head = self.catalog.head(tenant_id)
            self._headroom(head.manifest)
            with tempfile.TemporaryDirectory(prefix="writer-", dir=self.scratch) as folder:
                path = Path(folder)
                self.objects.restore(tenant_id, head.manifest, path)
                with self.catalog.engine.begin() as connection:
                    yield WorkspaceBinding(tenant_id, path, connection, lease.owner, lease.fence)
                    if lost.is_set():
                        raise Conflict("writer lease renewal failed")
                    from security_lakehouse.distributed.partitioning import prepare

                    partitions = prepare(path, tenant_id)
                    manifest = self.objects.snapshot(tenant_id, path, previous=head.manifest)
                    if partitions is not None:
                        manifest["partitions"] = partitions
                    if manifest == head.manifest:
                        # Nothing visible changed: keep the revision (and every
                        # reader cache) but still fence this transaction's writes.
                        self.catalog.confirm(lease, expected=head.version, connection=connection)
                    else:
                        self.catalog.publish(
                            tenant_id, expected=head.version, manifest=manifest, lease=lease, connection=connection
                        )
        finally:
            stop.set()
            heartbeat.join(timeout=15)
            try:
                self.catalog.release(lease)
            except Exception:  # noqa: BLE001 - fail closed at a distributed ownership boundary
                # A cleanup failure cannot undo a committed publication; the
                # database-clock lease expires without granting another writer.
                _log.warning("writer lease cleanup failed; awaiting expiry")

    @contextmanager
    def write(self, tenant_id: str, *, wait_seconds: float = 0):
        with self.transaction(tenant_id, wait_seconds=wait_seconds) as workspace:
            token = binding.set(workspace)
            try:
                yield workspace.path
            finally:
                binding.reset(token)

    @contextmanager
    def metadata_transaction(self, tenant_id: str):
        """Queue admission/cancellation never downloads or republishes tenant data."""
        self.catalog.ensure_tenant(tenant_id)
        with (
            tempfile.TemporaryDirectory(prefix="metadata-", dir=self.scratch) as folder,
            self.catalog.engine.begin() as connection,
        ):
            yield WorkspaceBinding(tenant_id, Path(folder), connection)
            if any(Path(folder).iterdir()):
                raise RuntimeError("metadata-only operation attempted a filesystem write")

    @contextmanager
    def metadata_read(self, tenant_id: str):
        with tempfile.TemporaryDirectory(prefix="metadata-read-", dir=self.scratch) as folder:
            yield WorkspaceBinding(tenant_id, Path(folder))
