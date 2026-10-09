"""Byte-level stability of the golden pipeline's clock-independent artifacts.

These artifacts do not embed wall-clock time or lake paths, so their bytes are
a pure function of the golden fixture, the shipped catalog, and evaluation
logic. Refactors must leave them unchanged. When an evaluation or catalog
change is intended, update the digests from the failure message.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from security_lakehouse.assessment import verify_snapshot_chain, write_assessment_snapshot
from security_lakehouse.fixtures import find_fixture
from security_lakehouse.golden_fixture import GOLDEN_COMPANY
from security_lakehouse.pipeline import run_pipeline

EXPECTED_SHA256 = {
    "gold/asset_risk.jsonl": "dba5fdaf83c3738723bf2b68e2c513ef843841e5c54615953b0faa3060a4f3fd",
    "gold/ccf_assessment.json": "bce806ad72bc7073e1184c3b98195473d0a2b2d118c527c4602928c1d0ecd7e9",
    "gold/control_posture.jsonl": "96cc35c09febafa9e0b1aeb13f4cbd78354f326724a7dba020ca6595491b9948",
    "gold/metrics.json": "fa1eb6e1311ca8f6e6b45fbf2b4b250e77fedafc4908feff6c9157470d5a2b00",
    "silver/normalized_events.jsonl": "1620e702198c4df792ef16201bbebfa748f89733f50a60f646ac0d902700b220",
}


def test_golden_pipeline_artifacts_are_byte_identical(tmp_path: Path) -> None:
    fixture = find_fixture(GOLDEN_COMPANY)
    assert fixture is not None
    lake = tmp_path / "lake"
    run_pipeline(fixture.raw_path, lake)

    actual = {rel: hashlib.sha256((lake / rel).read_bytes()).hexdigest() for rel in EXPECTED_SHA256}
    assert actual == EXPECTED_SHA256, json.dumps(actual, indent=2, sort_keys=True)

    write_assessment_snapshot(lake, reason="stability")
    write_assessment_snapshot(lake, reason="stability-2")
    chain = verify_snapshot_chain(lake)
    assert chain["ok"] is True, chain
