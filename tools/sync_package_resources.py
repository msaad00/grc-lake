"""Copy canonical deployment templates and schemas into importable package data."""

from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "src/security_lakehouse/resources"
SOURCES = {
    "cloud/aws-role.yaml": ROOT / "deploy/aws/trustops-posture-readonly-role.yaml",
    "cloud/aws-role.tf": ROOT / "deploy/aws/trustops-posture-readonly-role.tf",
    "cloud/gcp-reader.tf": ROOT / "deploy/gcp/trustops-posture-reader.tf",
    **{f"schemas/{path.name}": path for path in (ROOT / "data/schemas").glob("*.schema.json")},
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    stale = []
    for name, source in SOURCES.items():
        target = DESTINATION / name
        data = source.read_bytes()
        if target.is_file() and target.read_bytes() == data:
            continue
        if args.check:
            stale.append(name)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    if stale:
        print("Run python tools/sync_package_resources.py; stale resources: " + ", ".join(stale))
    return int(bool(stale))


if __name__ == "__main__":
    raise SystemExit(main())
