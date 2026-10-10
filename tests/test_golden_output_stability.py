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
    "gold/ccf_assessment.json": "f230793793c8695af41f3dc3f3900c7e48e08c886629e5f13748900c46c18c6b",
    "gold/control_posture.jsonl": "5afa613764cb5bfa3e8da8ef28516619a4812c480f156ef9a6e2490b25aa3725",
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

    # Catalog additions establish proposed coverage, never evidence or passes.
    assessment = json.loads((lake / "gold/ccf_assessment.json").read_text())
    requirements = {row["control_id"]: row for row in assessment["requirements"]}
    for control_id in ("NIST-800-171R3-03.09.01", "NIST-800-171R3-03.12.05"):
        assert requirements[control_id]["status"] == "not_evaluated"
        assert requirements[control_id]["pending_mapping_count"] == 1

    # Round-two catalog corrections retain context without granting coverage.
    pci = requirements["PCI-DSS-8"]
    assert pci["status"] == "unmapped"
    assert pci["pending_mapping_count"] == 0
    assert pci["contextual_mappings"] == [
        {"review_state": "proposed", "role": "supporting", "safeguard_id": "SG-IDENTITY-001"}
    ]
    gdpr = requirements["GDPR-Art.33"]
    assert gdpr["reviewed_safeguard_ids"] == []
    assert gdpr["pending_mapping_count"] == 1
    assert gdpr["contextual_mappings"] == [
        {
            "review_state": "maintainer_reviewed",
            "role": "supporting",
            "safeguard_id": "SG-INCIDENTRESPONSE-001",
        }
    ]

    write_assessment_snapshot(lake, reason="stability")
    write_assessment_snapshot(lake, reason="stability-2")
    chain = verify_snapshot_chain(lake)
    assert chain["ok"] is True, chain
