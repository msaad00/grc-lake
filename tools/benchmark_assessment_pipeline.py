"""Bounded synthetic full-pipeline measurements, not a production capacity claim."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import resource
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def worker(count: int) -> dict:
    from security_lakehouse.io import write_jsonl_from_iterable
    from security_lakehouse.pipeline import run_pipeline
    from security_lakehouse.scale_synthesis import iter_synthesize_audit_events
    from security_lakehouse.verification import verify_lake_integrity

    with tempfile.TemporaryDirectory(prefix="trustops-assessment-benchmark-") as folder:
        root = Path(folder)
        raw = root / "raw.jsonl"
        write_jsonl_from_iterable(
            raw,
            iter_synthesize_audit_events(
                count,
                controls_per_event=3,
                seed=42,
                base_time=datetime(2026, 10, 1, tzinfo=UTC),
            ),
        )
        raw_hash = hashlib.sha256(raw.read_bytes()).hexdigest()
        start = time.perf_counter()
        result = run_pipeline(raw, root / "lake", tenant_id="benchmark")
        seconds = time.perf_counter() - start
        valid = verify_lake_integrity(root / "lake")["ok"]
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
            "raw_sha256": raw_hash,
            "retained_bytes": sum(p.stat().st_size for p in (root / "lake/generations").rglob("*") if p.is_file()),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", nargs="+", type=int, choices=(1000, 10000), default=[1000, 10000])
    parser.add_argument("--repeats", type=int, choices=range(1, 6), default=3)
    parser.add_argument("--worker", type=int, choices=(1000, 10000), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker)))
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
            attempt = {"events": count, "repeat": repeat + 1}
            try:
                run = subprocess.run(
                    [sys.executable, str(Path(__file__).resolve()), "--worker", str(count)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    cwd=ROOT,
                )
                attempt.update(
                    json.loads(run.stdout) if run.returncode == 0 else {"failed": True, "returncode": run.returncode}
                )
            except subprocess.TimeoutExpired:
                attempt["timeout_seconds"] = 120
            attempts.append(attempt)
    result = {
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "tracked_diff_sha256": hashlib.sha256(diff).hexdigest(),
        "untracked_sha256": source_hashes,
        "measured_at": datetime.now(UTC).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "scope": "Synthetic, one tenant, sequential fresh processes; no concurrency or authenticated providers.",
        "bounds": {"max_events": 10000, "timeout_seconds_per_attempt": 120},
        "fixture": {"seed": 42, "controls_per_event": 3, "base_time": "2026-10-01T00:00:00Z"},
        "attempts": attempts,
    }
    print(json.dumps(result, indent=2))
    return 0 if all(r.get("integrity_ok") and r.get("silver_count") == r["events"] for r in attempts) else 1


if __name__ == "__main__":
    raise SystemExit(main())
