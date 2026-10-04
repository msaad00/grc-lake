"""Bounded synthetic reconciliation benchmark; excludes IO and integrity hashing."""

from __future__ import annotations

import argparse
import json
import statistics
import time
import tracemalloc

from security_lakehouse.population_reconciliation import reconcile_population


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=int, default=10000)
    args = parser.parse_args()
    if not 1 <= args.assets <= 100000:
        parser.error("--assets must be between 1 and 100000")
    events = [
        {
            "event_id": str(index),
            "tenant_id": "synthetic-source",
            "asset_id": str(index),
            "asset_type": "host",
            "event_time": "2026-01-03T00:00:00Z",
            "evidence_collected_at": "2026-01-03T01:00:00Z",
        }
        for index in range(args.assets)
    ]
    baseline = {
        "schema_version": "trustops.population_baseline.v1",
        "tenant_id": "synthetic-platform",
        "as_of": "2026-01-04T00:00:00Z",
        "max_age_days": 7,
        "inventory": {
            "source": "urn:synthetic:inventory",
            "owner": "synthetic-owner",
            "exported_at": "2026-01-03T00:00:00Z",
            "accounts": [{"source_tenant_id": "synthetic-source", "asset_ids": [row["asset_id"] for row in events]}],
        },
        "collections": [
            {
                "source_tenant_id": "synthetic-source",
                "source": "urn:synthetic:receipt",
                "status": "complete",
                "cursor_exhausted": True,
                "asset_count": len(events),
                "completed_at": "2026-01-03T02:00:00Z",
            }
        ],
    }
    timings = []
    for _ in range(3):
        start = time.perf_counter()
        report = reconcile_population(events, baseline)
        timings.append(time.perf_counter() - start)
        if report["status"] != "declared_scope_reconciled":
            raise RuntimeError("benchmark reconciliation failed")
    tracemalloc.start()
    reconcile_population(events, baseline)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(
        json.dumps(
            {
                "scope": "synthetic_in_memory_reconciliation_only",
                "assets": args.assets,
                "runs": 3,
                "median_seconds": statistics.median(timings),
                "peak_processing_bytes": peak,
                "excludes": ["input_allocation", "file_io", "generation_verification", "provider_collection"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
