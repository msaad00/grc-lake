"""Bounded synthetic full-pipeline measurements, not a production capacity claim."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SIZES = (1000, 10000, 100000)
TIMEOUT_SECONDS = 600
MAX_RSS_MIB = 4096
MIN_FREE_BYTES = 5 * 2**30


def worker(count: int, *, workload: str, root: Path, base_time: datetime) -> dict:
    from security_lakehouse.io import file_sha256, read_json, write_jsonl_from_iterable
    from security_lakehouse.pipeline import run_pipeline
    from security_lakehouse.scale_synthesis import iter_synthesize_audit_events
    from security_lakehouse.verification import verify_lake_integrity

    expected = {}

    def events():
        for index, row in enumerate(
            iter_synthesize_audit_events(count, controls_per_event=3, seed=42, base_time=base_time)
        ):
            if workload == "ccf":
                # Five independently labeled cases; neighboring source tenants
                # deliberately reuse asset IDs but never their evidence.
                case = index % 5
                row["tenant_id"] = f"source-{index % 2}"
                row["entity"] = {"asset_id": f"asset-{index // 2}", "asset_type": "iam_role"}
                row["status"] = ("pass", "failed", "unknown", "pass", "pass")[case]
                timestamp = (base_time - timedelta(days=3650) if case == 3 else base_time).isoformat()
                row["event_time"] = timestamp
                row["evidence"]["collected_at"] = timestamp
                row["safeguard_ids"] = [] if case == 4 else ["SG-IDENTITY-001"]
                if case != 4:
                    expected[(row["tenant_id"], row["entity"]["asset_id"])] = (
                        ("pass", "fail", "not_evaluated", "stale")[case],
                        row["event_id"],
                    )
            yield row

    raw = root / "raw.jsonl"
    write_jsonl_from_iterable(raw, events())
    raw_hash = file_sha256(raw)

    class EvaluationClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return base_time.astimezone(tz) if tz is not None else base_time.replace(tzinfo=None)

    # Keep predefined freshness labels stable across slow/repeated runs. Only
    # the synthetic pipeline clock is pinned; wall-time/resource guards are real.
    start = time.perf_counter()
    with patch("security_lakehouse.pipeline.datetime", EvaluationClock):
        result = run_pipeline(raw, root / "lake", tenant_id="benchmark")
    seconds = time.perf_counter() - start
    valid = verify_lake_integrity(root / "lake")["ok"]
    ccf = read_json(root / "lake/gold/ccf_assessment.json")
    details = ccf["asset_results"]
    actual = {(r["source_tenant_id"], r["asset_id"]): (r["status"], r["event_ids"]) for r in details}
    expected_details = {key: (status, [event_id]) for key, (status, event_id) in expected.items()}
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform != "darwin":
        rss *= 1024
    return {
        "events": count,
        "seconds": round(seconds, 3),
        "events_per_second": round(count / seconds, 1),
        "peak_rss_mib": round(rss / 2**20, 1),
        "silver_count": result.silver_count,
        "integrity_ok": valid,
        "ccf_labels_ok": actual == expected_details and len(details) == len(expected) and ccf["asset_count"] == count,
        "ccf_asset_count": ccf["asset_count"],
        "ccf_asset_result_count": len(details),
        "ccf_status_counts": dict(Counter(r["status"] for r in details)),
        "raw_sha256": raw_hash,
        "retained_bytes": sum(p.stat().st_size for p in (root / "lake/generations").rglob("*") if p.is_file()),
    }


def attempt(count: int, workload: str, base_time: str) -> dict:
    # Parent owns temporary storage so a killed worker cannot leak its lake.
    with tempfile.TemporaryDirectory(prefix="trustops-assessment-benchmark-") as folder:
        if shutil.disk_usage(folder).free < MIN_FREE_BYTES:
            return {"stopped": "disk_floor_before_start"}
        with tempfile.TemporaryFile(mode="w+") as output:
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--worker",
                    str(count),
                    "--workload",
                    workload,
                    "--root",
                    folder,
                    "--base-time",
                    base_time,
                ],
                stdout=output,
                stderr=subprocess.DEVNULL,
                cwd=ROOT,
            )
            started = time.monotonic()
            stopped = None
            try:
                while process.poll() is None:
                    if time.monotonic() - started > TIMEOUT_SECONDS:
                        stopped = "timeout"
                    elif shutil.disk_usage(folder).free < MIN_FREE_BYTES:
                        stopped = "disk_floor"
                    else:
                        rss = subprocess.run(
                            ["ps", "-o", "rss=", "-p", str(process.pid)], capture_output=True, text=True
                        )
                        if rss.returncode == 0 and rss.stdout.strip() and int(rss.stdout.strip()) > MAX_RSS_MIB * 1024:
                            stopped = "rss_limit"
                    if stopped:
                        process.kill()
                        break
                    time.sleep(0.25)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
            if stopped:
                return {"stopped": stopped, "elapsed_seconds": round(time.monotonic() - started, 3)}
            if process.returncode:
                return {"failed": True, "returncode": process.returncode}
            output.seek(0)
            return json.load(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", nargs="+", type=int, choices=SIZES, default=[1000, 10000])
    parser.add_argument("--repeats", type=int, choices=range(1, 6), default=3)
    parser.add_argument("--workload", choices=("framework", "ccf"), default="framework")
    parser.add_argument("--base-time", default=datetime.now(UTC).isoformat())
    parser.add_argument("--worker", type=int, choices=SIZES, help=argparse.SUPPRESS)
    parser.add_argument("--root", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        print(
            json.dumps(
                worker(
                    args.worker,
                    workload=args.workload,
                    root=args.root,
                    base_time=datetime.fromisoformat(args.base_time),
                )
            )
        )
        return 0
    diff = subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=ROOT)
    untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=ROOT)
    source_hashes = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in untracked.decode().split("\0")
        if name and (ROOT / name).is_file()
    }
    attempts = []
    for count in args.sizes:
        for repeat in range(args.repeats):
            row = {"events": count, "repeat": repeat + 1, **attempt(count, args.workload, args.base_time)}
            attempts.append(row)
            if not (row.get("integrity_ok") and row.get("ccf_labels_ok") and row.get("silver_count") == count):
                break
        else:
            continue
        break  # Never increase load after a failed or bounded-out attempt.
    result = {
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "tracked_diff_sha256": hashlib.sha256(diff).hexdigest(),
        "untracked_sha256": source_hashes,
        "measured_at": datetime.now(UTC).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "scope": "Synthetic, one platform tenant, sequential fresh processes; no concurrency or authenticated providers.",
        "bounds": {
            "max_events": max(SIZES),
            "timeout_seconds_per_attempt": TIMEOUT_SECONDS,
            "sampled_rss_limit_mib": MAX_RSS_MIB,
            "disk_free_floor_bytes": MIN_FREE_BYTES,
            "sampling_interval_seconds": 0.25,
        },
        "fixture": {"seed": 42, "controls_per_event": 3, "base_time": args.base_time, "workload": args.workload},
        "attempts": attempts,
    }
    print(json.dumps(result, indent=2))
    return (
        0
        if all(
            r.get("integrity_ok") and r.get("ccf_labels_ok") and r.get("silver_count") == r["events"] for r in attempts
        )
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
