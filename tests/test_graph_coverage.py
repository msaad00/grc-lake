"""Coverage & gap analysis over the directed compliance graph (BR-7).

``analyze_coverage`` follows ``framework -> control -> evidence -> asset`` and
reports which assets are reached by control evidence, which controls have no
evidence (orphans), and which frameworks have no covered control. This is
compliance coverage/gap analysis, not infra attack-path reachability.
"""

from __future__ import annotations

import json
from http import HTTPStatus
from pathlib import Path

import pytest

from security_lakehouse.graph import analyze_coverage
from test_api_v1 import _seed_lake, _write_jsonl


def _seed_lake_with_gap(lake: Path) -> None:
    """Seed a lake where one asset has evidence and one asset has none.

    ``SOC2-CC6.1`` is a real catalog control, so its evidence wires a covered
    asset. ``orphan:db`` appears only in the asset table with no evidence event,
    so it must surface as an uncovered gap / orphan asset.
    """
    _write_jsonl(
        lake / "silver" / "normalized_events.jsonl",
        [
            {
                "event_id": "evt-001",
                "event_time": "2026-05-20T13:01:00Z",
                "event_type": "identity.access_review",
                "control_ids": ["SOC2-CC6.1"],
                "asset_id": "aws:iam:role/admin",
                "asset_owner": "security-platform",
                "asset_type": "iam_role",
                "environment": "prod",
                "source": "okta",
                "status": "open",
                "severity": "high",
                "severity_score": 80,
                "evidence_ref": "s3://evidence/evt-001.json",
                "raw_sha256": "abc",
            }
        ],
    )
    _write_jsonl(
        lake / "gold" / "asset_risk.jsonl",
        [
            {
                "asset_id": "aws:iam:role/admin",
                "asset_owner": "security-platform",
                "asset_type": "iam_role",
                "environment": "prod",
                "risk_score": 80,
            },
            {
                "asset_id": "orphan:db",
                "asset_owner": "data-platform",
                "asset_type": "database",
                "environment": "prod",
                "risk_score": 60,
            },
        ],
    )


def test_coverage_detects_covered_assets(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    report = analyze_coverage(tmp_path)

    by_id = {asset["asset_id"]: asset for asset in report["assets"]}
    covered = by_id["asset:aws\\:iam\\:role/admin"]
    assert covered["covered"] is True
    assert covered["is_gap"] is False
    assert [c["id"] for c in covered["controls"]] == ["control:SOC2-CC6.1"]
    assert [f["id"] for f in covered["frameworks"]] == ["framework:soc2"]

    # Both seeded assets have evidence, so coverage is total.
    assert report["summary"]["covered_assets"] == report["summary"]["total_assets"]
    assert report["summary"]["coverage_pct"] == 100.0


def test_coverage_flags_orphan_asset_as_gap(tmp_path: Path) -> None:
    _seed_lake_with_gap(tmp_path)
    report = analyze_coverage(tmp_path)

    by_id = {asset["asset_id"]: asset for asset in report["assets"]}
    gap = by_id["asset:orphan\\:db"]
    assert gap["covered"] is False
    assert gap["is_gap"] is True
    assert gap["controls"] == []

    orphan_asset_ids = {entry["id"] for entry in report["orphans"]["assets"]}
    assert "asset:orphan\\:db" in orphan_asset_ids
    assert "asset:aws\\:iam\\:role/admin" not in orphan_asset_ids


def test_coverage_summary_counts_and_pct(tmp_path: Path) -> None:
    _seed_lake_with_gap(tmp_path)
    report = analyze_coverage(tmp_path)
    summary = report["summary"]

    assert summary["total_assets"] == 2
    assert summary["covered_assets"] == 1
    assert summary["uncovered_assets"] == 1
    assert summary["coverage_pct"] == 50.0

    # Exactly one catalog control (SOC2-CC6.1) has evidence; the rest are orphans.
    assert summary["covered_controls"] == 1
    assert summary["orphan_controls"] == summary["total_controls"] - 1
    orphan_control_ids = {entry["id"] for entry in report["orphans"]["controls"]}
    assert "control:SOC2-CC6.1" not in orphan_control_ids
    assert len(orphan_control_ids) == min(summary["orphan_controls"], report["detail_limit"])


def test_coverage_orphan_frameworks(tmp_path: Path) -> None:
    _seed_lake_with_gap(tmp_path)
    report = analyze_coverage(tmp_path)

    orphan_framework_ids = {entry["id"] for entry in report["orphans"]["frameworks"]}
    # soc2 has a covered control, so it is not an orphan framework.
    assert "framework:soc2" not in orphan_framework_ids
    assert report["summary"]["orphan_frameworks"] == len(orphan_framework_ids)


def test_coverage_is_json_serialisable_and_deterministic(tmp_path: Path) -> None:
    _seed_lake_with_gap(tmp_path)
    first = analyze_coverage(tmp_path)
    second = analyze_coverage(tmp_path)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


# --- headless HTTP surface -------------------------------------------------

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient  # noqa: E402

from security_lakehouse import api_v1  # noqa: E402
from security_lakehouse.server_app import create_app  # noqa: E402


def test_coverage_is_in_resource_catalog() -> None:
    catalog = api_v1.resource_catalog()
    entry = next((row for row in catalog if row["path"] == "/api/v1/graph/coverage"), None)
    assert entry is not None
    assert entry["resource"] == "graph.coverage"
    assert entry["kind"] == "singleton"
    assert entry["methods"] == ["GET"]


def test_http_coverage_returns_v1_envelope(tmp_path: Path) -> None:
    _seed_lake_with_gap(tmp_path)
    client = TestClient(create_app(tmp_path, require_auth=False))

    response = client.get("/api/v1/graph/coverage")
    assert response.status_code == HTTPStatus.OK
    body = response.json()
    assert body["errors"] == []
    assert body["meta"]["api_version"] == "v1"
    assert body["meta"]["resource"] == "graph.coverage"

    data = body["data"]
    assert data["summary"]["total_assets"] == 2
    assert data["summary"]["covered_assets"] == 1
    assert data["summary"]["coverage_pct"] == 50.0
    gap_assets = {entry["id"] for entry in data["orphans"]["assets"]}
    assert "asset:orphan\\:db" in gap_assets
