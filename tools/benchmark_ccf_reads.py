"""Bounded, instrumented CCF projection reads; not HTTP or full-pipeline capacity."""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import platform
import sqlite3
import subprocess
import sys
import tempfile
import time
import tracemalloc
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fixture(root: Path, count: int) -> None:
    from security_lakehouse.ccf_queries import write_projection
    from security_lakehouse.io import write_json

    assessment = {
        "schema_version": "trustops.ccf_assessment.v1",
        "scope": "observed_assets",
        "population_completeness": "not_established",
        "safeguards": [],
        "requirements": [],
        "asset_results": [
            {
                "safeguard_id": "SG-fixture",
                "source_tenant_id": f"source-{i % 2}",
                "asset_id": f"asset-{i:09d}",
                "status": "pass" if i % 2 == 0 else "fail",
                "event_ids": [f"event-{i}"],
                "evidence_hashes": ["a" * 64],
                "reasons": ["Synthetic fixture."],
            }
            for i in range(count)
        ],
    }
    write_json(root / "gold/ccf_assessment.json", assessment)
    # Minimal projection metadata, deliberately not a sealed full assessment.
    write_json(root / "generation.json", {"ccf_projection_version": 1})
    (root / "mart").mkdir()
    with sqlite3.connect(root / "mart/security_lakehouse.sqlite") as connection:
        write_projection(connection, assessment)


def read(root: Path, mode: str) -> dict:
    from security_lakehouse.api_v1 import collection_response
    from security_lakehouse.ccf_queries import read_page

    gc.collect()
    tracemalloc.start()
    start = time.perf_counter()
    if mode == "legacy":
        rows = json.loads((root / "gold/ccf_assessment.json").read_text())["asset_results"]
        result = collection_response(
            "ccf.asset-results", rows, {"status": ["pass"], "sort": ["asset_id"], "limit": ["25"]}
        )
        page, count = result["data"], result["meta"]["count"]
    else:
        page, count = read_page(root, filters={"status": ["pass"]}, sort="asset_id", limit=25, offset=0)
    seconds = time.perf_counter() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "mode": mode,
        "seconds_with_tracemalloc": round(seconds, 6),
        "peak_python_mib": round(peak / 2**20, 3),
        "count": count,
        "returned": len(page),
        "asset_ids": [row["asset_id"] for row in page],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="+", choices=(1000, 10000, 100000), default=[1000, 10000, 100000])
    parser.add_argument("--repeats", type=int, choices=range(1, 4), default=3)
    parser.add_argument("--worker", choices=("legacy", "indexed"), help=argparse.SUPPRESS)
    parser.add_argument("--root", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(read(args.root, args.worker)))
        return 0
    results = []
    for size in args.sizes:
        with tempfile.TemporaryDirectory(prefix="trustops-ccf-reads-") as folder:
            root = Path(folder)
            fixture(root, size)
            from security_lakehouse.io import file_sha256

            dataset_hash = file_sha256(root / "gold/ccf_assessment.json")
            for mode in ("legacy", "indexed"):
                for repeat in range(args.repeats):
                    record = {"assets": size, "mode": mode, "repeat": repeat + 1, "fixture_sha256": dataset_hash}
                    try:
                        child = subprocess.run(
                            [sys.executable, __file__, "--worker", mode, "--root", folder],
                            text=True,
                            capture_output=True,
                            timeout=60,
                            cwd=ROOT,
                        )
                        record.update(
                            json.loads(child.stdout)
                            if child.returncode == 0
                            else {"failed": True, "returncode": child.returncode}
                        )
                    except subprocess.TimeoutExpired:
                        record["timeout_seconds"] = 60
                    record["ok"] = (
                        record.get("count") == size // 2
                        and record.get("returned") == 25
                        and record.get("asset_ids") == [f"asset-{i:09d}" for i in range(0, 50, 2)]
                    )
                    record.pop("asset_ids", None)
                    results.append(record)
    diff = subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=ROOT)
    untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=ROOT)
    print(
        json.dumps(
            {
                "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "tracked_diff_sha256": hashlib.sha256(diff).hexdigest(),
                "untracked_files": untracked.decode().split("\0")[:-1],
                "measured_at": datetime.now(UTC).isoformat(),
                "python": platform.python_version(),
                "platform": platform.platform(),
                "scope": "Fresh-process reads of a synthetic SQL projection; Python allocations with tracemalloc, not total RSS. No HTTP, full pipeline, or concurrent writers.",
                "attempts": results,
            },
            indent=2,
        )
    )
    return 0 if all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
