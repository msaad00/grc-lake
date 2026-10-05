#!/usr/bin/env python3
"""Measure warm reads of synthetic snapshot history; not a capacity estimate."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from security_lakehouse import assessment, ledger, strict_json
from security_lakehouse.db import metrics
from security_lakehouse.db.metrics import framework_readiness_trends


def measure(call: Callable, repeats: int) -> float:
    call()  # Warm the verification and filesystem caches before measuring.
    timings = []
    for _ in range(repeats):
        started = time.perf_counter()
        call()
        timings.append(time.perf_counter() - started)
    return round(statistics.median(timings), 6)


def benchmark(snapshots: int, events: int, repeats: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="trustops-snapshot-benchmark-") as temp:
        lake = Path(temp)
        directory = lake / "gold/snapshots"
        directory.mkdir(parents=True)
        rows = [
            {
                "event_id": f"e-{index}",
                "asset_id": f"asset-{index % 50}",
                "status": "pass",
                "note": "Evidence content " * 8,
            }
            for index in range(events)
        ]
        entries = []
        previous = None
        for day in range(snapshots):
            payload = {
                "evaluated_at": (datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=day)).isoformat(),
                "prev_hash": previous,
                "posture": {"score": 75},
                "frameworks": [{"framework": "SOC 2", "score": 75}],
                "evidence": rows,
            }
            payload["assessment_hash"] = assessment._assessment_hash(payload)
            path = directory / f"assessment-{day:03}.json"
            path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            entries.append(
                {key: payload[key] for key in ("evaluated_at", "prev_hash", "assessment_hash")}
                | {"snapshot": path.name}
            )
            previous = payload["assessment_hash"]
        (directory / "_ledger.jsonl").write_text("".join(json.dumps(row) + "\n" for row in entries), encoding="utf-8")
        raw = path.read_bytes()
        return {
            "scope": "synthetic warm snapshot reads; not pipeline capacity or a cold-start estimate",
            "python": platform.python_version(),
            "platform": platform.platform(),
            "source_sha256": {
                module.__name__: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
                for module in (assessment, ledger, strict_json, metrics)
            },
            "snapshots": snapshots,
            "events_per_snapshot": events,
            "repeats": repeats,
            "total_bytes": sum(item.stat().st_size for item in directory.glob("*.json")),
            "strict_decode_seconds": measure(lambda: strict_json.loads(raw), repeats),
            "load_snapshot_seconds": measure(lambda: assessment.load_snapshot(lake, path.stem), repeats),
            "trends_limit_3_seconds": measure(
                lambda: framework_readiness_trends(lake, limit=3, include_current=False), repeats
            ),
            "verify_seconds": measure(lambda: assessment.verify_snapshot_chain(lake), repeats),
        }


def positive(value: str) -> int:
    result = int(value)
    if result < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshots", type=positive, default=20)
    parser.add_argument("--events", type=positive, default=2000)
    parser.add_argument("--repeats", type=positive, default=3)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.snapshots, args.events, args.repeats), indent=2))


if __name__ == "__main__":
    main()
