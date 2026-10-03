from __future__ import annotations

import json
from pathlib import Path

from security_lakehouse.cli import main
from security_lakehouse.io import read_json

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw" / "security_events.jsonl"


def test_ingestion_normalize_materializes_prelanded_raw_events_with_provenance(tmp_path: Path) -> None:
    lake = tmp_path / "lake"

    assert main(["ingestion", "normalize", "--raw", str(RAW), "--out", str(lake)]) == 0

    manifest = read_json(lake / "manifest.json")
    assert manifest["normalization"] == {
        "input_contract": "trustops.raw_event.v1",
        "schema_version": "trustops.normalized_event.v1",
        "transform_version": "trustops.normalization.v2",
    }
    assert manifest["row_counts"]["silver"] == 10
    assert (lake / "gold" / "current_posture.json").is_file()


def test_ingestion_normalize_replay_is_idempotent(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    first = main(["ingestion", "normalize", "--raw", str(RAW), "--out", str(lake)])
    before = (lake / "silver" / "normalized_events.jsonl").read_text(encoding="utf-8")

    second = main(["ingestion", "normalize", "--raw", str(RAW), "--out", str(lake), "--incremental"])
    after = (lake / "silver" / "normalized_events.jsonl").read_text(encoding="utf-8")

    assert first == second == 0
    assert after == before
    manifest = json.loads((lake / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["materialize_mode"] == "full"
