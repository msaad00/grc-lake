"""Bounded multi-tenant PostgreSQL/S3-emulator benchmark, never production capacity."""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import resource
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenants", type=int, default=4)
    parser.add_argument("--rows", type=int, default=1000, help="synthetic rows per tenant, at most 25000")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.tenants <= 8 or not 1 <= args.rows <= 25000:
        parser.error("bounded run requires 1-8 tenants and 1-25000 rows per tenant")
    from moto.server import ThreadedMotoServer
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    from security_lakehouse.db.migrate import upgrade
    from security_lakehouse.distributed.catalog import Catalog
    from security_lakehouse.distributed.commands import download_partitions
    from security_lakehouse.distributed.config import ClusterConfig
    from security_lakehouse.distributed.objects import ObjectStore
    from security_lakehouse.distributed.workspace import Runtime
    from security_lakehouse.io import write_jsonl_from_iterable
    from security_lakehouse.pipeline import run_pipeline
    from security_lakehouse.scale_synthesis import iter_synthesize_audit_events

    url = os.environ["TEST_POSTGRES_URL"]
    database = "grc_benchmark_" + uuid.uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    engine = None
    server = ThreadedMotoServer(ip_address="127.0.0.1", port=0, verbose=False)
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    server.start()
    os.environ["AWS_ACCESS_KEY_ID"] = "test-access"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "test-secret"
    os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{database}"'))
    try:
        target_url = make_url(url).set(database=database)
        upgrade(".", url=target_url.render_as_string(hide_password=False))
        engine = create_engine(target_url, pool_size=20)
        host, port = server.get_host_and_port()
        config = ClusterConfig("benchmark", "benchmark-bucket", endpoint=f"http://{host}:{port}")
        catalog = Catalog(engine, config)
        catalog.initialize()
        objects = ObjectStore(config)
        objects.client.create_bucket(Bucket=config.bucket)
        objects.verify_conditional_writes()
        with tempfile.TemporaryDirectory(prefix="grc-benchmark-") as folder:
            root = Path(folder)

            def run(index):
                tenant = f"benchmark-{index}"
                raw = root / f"raw-{index}.jsonl"
                write_jsonl_from_iterable(raw, iter_synthesize_audit_events(args.rows, seed=42 + index))
                writer = Runtime(catalog, ObjectStore(config), root / f"writer-{index}")
                start = time.perf_counter()
                with writer.write(tenant) as lake:
                    run_pipeline(raw, lake, tenant_id=tenant)
                published = time.perf_counter()
                reader = Runtime(catalog, ObjectStore(config), root / f"reader-{index}")
                with reader.read(tenant) as lake:
                    assert (lake / "silver/normalized_events.jsonl").exists()
                cold = time.perf_counter()
                with reader.read(tenant):
                    pass
                warm = time.perf_counter()
                head = catalog.head(tenant)
                manifest = head.manifest["partitions"]
                source = manifest["partitions"][0]["source"]
                subset = download_partitions(reader, tenant, root / f"partition-{index}", source=source)
                selected = time.perf_counter()
                assert manifest["row_count"] == args.rows
                return {
                    "tenant": tenant,
                    "shard": config.shard_for(tenant),
                    "rows": args.rows,
                    "publish_seconds": published - start,
                    "cold_read_seconds": cold - published,
                    "warm_read_seconds": warm - cold,
                    "partition_download_seconds": selected - warm,
                    "partition_rows": subset["row_count"],
                    "partition_files": len(subset["partitions"]),
                    "lake_bytes": sum(entry["size"] for entry in head.manifest["files"].values()),
                    "partition_bytes": sum(entry["size"] for entry in subset["partitions"]),
                }

            start = time.perf_counter()
            with ThreadPoolExecutor(args.tenants) as pool:
                results = list(pool.map(run, range(args.tenants)))
            elapsed = time.perf_counter() - start
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        report = {
            "evidence": "synthetic-local-postgresql-and-s3-http-emulator",
            "platform": platform.platform(),
            "python": platform.python_version(),
            "concurrent_tenants": args.tenants,
            "rows_per_tenant": args.rows,
            "elapsed_seconds": elapsed,
            "process_peak_rss_mib": rss / (1024**2 if platform.system() == "Darwin" else 1024),
            "results": results,
            "limitations": [
                "one host",
                "emulated S3",
                "thread concurrency",
                "synthetic evidence",
                "not a production SLO",
            ],
        }
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"report": str(args.out), "seconds": elapsed, "verified_rows": args.rows * args.tenants}))
        return 0
    finally:
        if engine is not None:
            engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE "{database}" WITH (FORCE)'))
        admin.dispose()
        server.stop()


if __name__ == "__main__":
    raise SystemExit(main())
