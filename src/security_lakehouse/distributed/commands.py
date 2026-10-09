"""Operator commands for PostgreSQL/S3 clusters; local mode stays unchanged."""

from __future__ import annotations

import json
import shutil
import signal
import tempfile
from functools import partial
from pathlib import Path


def register(subparsers):
    cluster = subparsers.add_parser("cluster", help="distributed PostgreSQL/S3 cluster operations")
    commands = cluster.add_subparsers(dest="cluster_command", required=True)
    for name in ("init", "status", "import", "worker", "partitions"):
        command = commands.add_parser(name)
        command.add_argument("--lake", default="/lake", help="replica-private scratch directory")
        command.set_defaults(func=run)
        if name in {"status", "import", "partitions"}:
            command.add_argument("--tenant-id", required=True)
        if name == "import":
            command.add_argument("--source", required=True, help="verified single-tenant source lake")
        if name == "worker":
            command.add_argument("--shards", default="all", help="comma-separated virtual shard IDs or all")
            command.add_argument("--concurrency", type=int, default=2)
            command.add_argument("--once", action="store_true")
        if name == "partitions":
            command.add_argument("--out", required=True, help="new directory for selected verified Parquet files")
            command.add_argument("--source")
            command.add_argument("--start-date")
            command.add_argument("--end-date")


def _shards(raw, config):
    if raw == "all":
        return None
    values = {int(value) for value in raw.split(",")}
    if not values or any(value < 0 or value >= config.shards for value in values):
        raise ValueError("worker shard IDs must belong to the configured cluster")
    return values


def run(args) -> int:
    from security_lakehouse.db.base import create_engine_for, session_factory
    from security_lakehouse.db.migrate import upgrade
    from security_lakehouse.distributed.catalog import Catalog
    from security_lakehouse.distributed.config import ClusterConfig
    from security_lakehouse.distributed.objects import ObjectStore
    from security_lakehouse.distributed.workspace import Runtime

    config = ClusterConfig.from_env()
    if config is None:
        raise ValueError("cluster commands require GRC_LAKE_DEPLOYMENT_MODE=distributed")
    root = Path(args.lake).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    upgrade(root)
    engine = create_engine_for(root)
    try:
        catalog = Catalog(engine, config)
        catalog.initialize()
        objects = ObjectStore(config)
        runtime = Runtime(catalog, objects, root / "distributed-scratch")
        factory = session_factory(engine)
        if args.cluster_command == "init":
            objects.client.head_bucket(Bucket=config.bucket)
            objects.verify_conditional_writes()
            result = {"cluster_id": config.cluster_id, "virtual_shards": config.shards, "ready": True}
        elif args.cluster_command == "status":
            head = catalog.head(args.tenant_id)
            result = {
                "tenant_id": head.tenant_id,
                "version": head.version,
                "shard": config.shard_for(head.tenant_id),
                "files": len(head.manifest.get("files", {})),
                "bytes": sum(entry["size"] for entry in head.manifest.get("files", {}).values()),
            }
        elif args.cluster_command == "import":
            result = import_lake(runtime, factory, Path(args.source), args.tenant_id)
        elif args.cluster_command == "partitions":
            result = download_partitions(
                runtime,
                args.tenant_id,
                Path(args.out),
                source=args.source,
                start_date=args.start_date,
                end_date=args.end_date,
            )
        else:
            from security_lakehouse.operation_execution import execute_operation, execute_stored_operation
            from security_lakehouse.operation_jobs import JobQueue, JobWorker

            queue = JobQueue(factory, root, shards=_shards(args.shards, config))
            worker = JobWorker(
                queue,
                partial(execute_operation, root, factory=factory, require_auth=True),
                subprocess_execute=partial(execute_stored_operation, require_auth=True),
                concurrency=args.concurrency,
            )
            if args.once:
                result = {"worked": worker.run_once(isolated=True)}
            else:

                def stop(signum, frame):
                    worker.stop_event.set()

                previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM)}
                try:
                    worker.start()
                    while not worker.stop_event.wait(1):
                        pass
                finally:
                    worker.stop()
                    for sig, handler in previous.items():
                        signal.signal(sig, handler)
                result = {"stopped": True}
        print(json.dumps(result, sort_keys=True))
        return 0
    finally:
        engine.dispose()


def import_lake(runtime, factory, source: Path, tenant_id: str) -> dict:
    from security_lakehouse.db.models import Tenant
    from security_lakehouse.generations import pin_generation, verify_generation
    from security_lakehouse.io import read_json

    source = source.resolve()
    if source == runtime.scratch or source.is_relative_to(runtime.scratch) or runtime.scratch.is_relative_to(source):
        raise ValueError("import source and replica scratch must not overlap")
    with factory() as session:
        if session.get(Tenant, tenant_id) is None:
            raise ValueError("import requires an existing authenticated tenant")
    if (source / "server").exists() or (source / "tenants").exists():
        raise ValueError("import a single tenant lake, never a server or tenant root")
    with pin_generation(source) as generation:
        if generation is None:
            raise ValueError("import requires a sealed assessment generation")
        verify_generation(generation)
        if read_json(generation / "manifest.json").get("tenant_id") != tenant_id:
            raise ValueError("source assessment does not belong to the target tenant")
        # Validate the complete layout before following any links during copy.
        runtime.objects.snapshot(tenant_id, source)
        with runtime.write(tenant_id) as target:
            if runtime.catalog.head(tenant_id).version != 0:
                raise ValueError("target tenant already has a published lake")
            shutil.copytree(source, target, dirs_exist_ok=True, symlinks=True)
    return {"tenant_id": tenant_id, "version": runtime.catalog.head(tenant_id).version}


def download_partitions(runtime, tenant_id: str, target: Path, **filters) -> dict:
    from security_lakehouse.distributed.objects import _relative
    from security_lakehouse.distributed.partitioning import select_partitions
    from security_lakehouse.generations import publication_lock

    head = runtime.catalog.head(tenant_id)
    manifest = head.manifest.get("partitions")
    if manifest is None:
        raise ValueError("tenant has no published partitioned assessment")
    selected = select_partitions(manifest, tenant_id=tenant_id, **filters)
    target = target.absolute()
    if target.exists() or target.is_symlink():
        raise FileExistsError("partition output already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".download-", dir=target.parent) as folder:
        staged = Path(folder) / "bundle"
        staged.mkdir(mode=0o700)
        for part in selected:
            relative = _relative(part["path"])
            entry = head.manifest["files"]["_distributed/analytics/" + str(relative)]
            if entry != {"sha256": part["sha256"], "size": part["size"]}:
                raise ValueError("partition metadata differs from published object")
            runtime.objects.get(tenant_id, entry, staged / relative)
        result = {
            **manifest,
            "partitions": selected,
            "row_count": sum(p["row_count"] for p in selected),
            "publication_version": head.version,
        }
        (staged / "manifest.json").write_text(json.dumps(result, sort_keys=True) + "\n")
        with publication_lock(target.parent):
            if target.exists() or target.is_symlink():
                raise FileExistsError("partition output already exists")
            staged.rename(target)
    return result
