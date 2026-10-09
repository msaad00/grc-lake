"""AI governance platform API and aggregation tests."""

from __future__ import annotations

from datetime import UTC, datetime
from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from security_lakehouse.ai_governance import build_ai_governance_status, list_ai_inventory
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake, _write_jsonl


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _seed_ai_events(lake: Path) -> None:
    _seed_lake(lake)
    _write_jsonl(
        lake / "silver" / "normalized_events.jsonl",
        [
            {
                "event_id": "evt-ai-001",
                "event_time": "2026-05-20T15:05:00Z",
                "event_type": "ai.model_inventory",
                "control_ids": ["NIST-AI-RMF-MAP-1.5", "ISO42001-8.1", "EU-AI-ACT-Art.10"],
                "asset_id": "model:customer-support-reranker:v3",
                "asset_owner": "ai-security",
                "asset_type": "ai_model",
                "environment": "prod",
                "source": "model-registry",
                "status": "passed",
                "severity": "low",
                "severity_score": 10,
                "evidence_ref": "s3://evidence/model-card.json",
                "raw_sha256": "abc",
                "attributes": {"model_card": True, "lineage_complete": True},
            },
            {
                "event_id": "evt-ai-002",
                "event_time": "2026-05-22T08:30:00Z",
                "event_type": "model.lineage",
                "control_ids": ["NIST-AI-RMF-MAP-1.5"],
                "asset_id": "model:customer-support-reranker:v3",
                "asset_owner": "ai-security",
                "asset_type": "ai_model",
                "environment": "prod",
                "source": "model-registry",
                "status": "passed",
                "severity": "info",
                "severity_score": 5,
                "evidence_ref": "s3://evidence/lineage.json",
                "raw_sha256": "def",
            },
            {
                "event_id": "evt-ai-003",
                "event_time": "2026-05-20T13:11:00Z",
                "event_type": "runtime.tool_call",
                "control_ids": ["NIST-AI-RMF-MANAGE-4.3", "EU-AI-ACT-Art.14"],
                "asset_id": "agent:finance-research",
                "asset_owner": "ai-security",
                "asset_type": "ai_agent",
                "environment": "prod",
                "source": "runtime-gateway",
                "status": "blocked",
                "severity": "high",
                "severity_score": 80,
                "evidence_ref": "s3://evidence/runtime.json",
                "raw_sha256": "ghi",
            },
            {
                "event_id": "evt-ai-004",
                "event_time": "2026-05-20T16:00:00Z",
                "event_type": "repository.ai_artifact",
                "control_ids": ["NIST-AI-RMF-MAP-1.5", "EU-AI-ACT-Art.10", "ISO42001-8.1"],
                "asset_id": "github:repo:acme/ml-platform",
                "asset_owner": "ai-security",
                "asset_type": "repository",
                "environment": "public",
                "source": "github-public-repo",
                "status": "observed",
                "severity": "info",
                "severity_score": 0,
                "evidence_ref": "https://github.com/acme/ml-platform",
                "raw_sha256": "jkl",
                "attributes": {"paths": ["modelcard.md"], "path_count": 1},
            },
        ],
    )


def test_build_ai_governance_status_fixture(tmp_path: Path) -> None:
    _seed_ai_events(tmp_path)
    data = build_ai_governance_status(lake=tmp_path)
    assert data["inventory"]["models"] >= 1
    assert data["inventory"]["agents"] >= 1
    assert data["events"]["model_inventory"] >= 1
    assert data["events"]["model_lineage"] >= 1
    assert data["events"]["agent_runtime"] >= 1
    assert data["events"]["repo_artifacts"] >= 1
    assert data["frameworks_total"] == 3
    assert data["aibom"]["shipped"] is True
    assert data["evidence_loops"]["inventory_events"] is True
    assert data["evidence_loops"]["lineage_events"] is True


def test_list_ai_inventory_fixture(tmp_path: Path) -> None:
    _seed_ai_events(tmp_path)
    rows = list_ai_inventory(lake=tmp_path)
    asset_ids = {row["asset_id"] for row in rows}
    assert "model:customer-support-reranker:v3" in asset_ids
    assert "agent:finance-research" in asset_ids


def test_ai_governance_api(tmp_path: Path) -> None:
    _seed_ai_events(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    with app.state.sessionmaker() as session:
        tenant = create_tenant(session, slug="ai-gov", name="AI Gov")
        user = create_user(session, tenant_id=tenant.id, email="read@ai-gov.test", role="read_only")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        session.commit()
    resp = client.get("/api/v1/platform/ai-governance", headers=_bearer(token))
    assert resp.status_code == HTTPStatus.OK
    body = resp.json()["data"]
    assert body["governance_score"] >= 0
    assert len(body["frameworks"]) == 3

    inv = client.get("/api/v1/platform/ai-governance/inventory", headers=_bearer(token))
    assert inv.status_code == HTTPStatus.OK
    assert len(inv.json()["data"]) >= 2


def test_build_ai_governance_empty_lake_gaps(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    _write_jsonl(
        tmp_path / "silver" / "normalized_events.jsonl",
        [
            {
                "event_id": "evt-non-ai",
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
                "evidence_ref": "s3://evidence/evt-non-ai.json",
                "raw_sha256": "abc",
            }
        ],
    )
    data = build_ai_governance_status(lake=tmp_path)
    assert data["state"] == "needs_work"
    gap_ids = {gap["id"] for gap in data["gaps"]}
    assert gap_ids == {"model_inventory", "model_lineage", "model_cards", "agent_governance"}
    assert data["evidence_loops"]["inventory_events"] is False
    assert data["aibom"]["shipped"] is True


def test_complete_inventory_without_passing_controls_is_not_governed(tmp_path: Path) -> None:
    _seed_ai_events(tmp_path)
    data = build_ai_governance_status(lake=tmp_path)
    assert data["governance_score"] < 85
    assert data["state"] != "governed"
    assert data["gaps"] == []


def test_list_ai_inventory_pagination(tmp_path: Path) -> None:
    _seed_ai_events(tmp_path)
    page = list_ai_inventory(lake=tmp_path, limit=1, offset=0)
    assert len(page) == 1
    rest = list_ai_inventory(lake=tmp_path, limit=10, offset=1)
    assert page[0]["asset_id"] != rest[0]["asset_id"]


def test_ai_governance_api_requires_auth(tmp_path: Path) -> None:
    _seed_ai_events(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    resp = client.get("/api/v1/platform/ai-governance")
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.parametrize("status", ["fail", "unknown"])
def test_evidence_presence_does_not_make_ai_posture_pass(status):
    from security_lakehouse.ai_governance import _framework_rows

    control_id = "NIST-AI-RMF-GOVERN-1.1"
    rows = _framework_rows(
        controls=[{"control_id": control_id, "status": status}],
        events=[{"control_ids": [control_id], "status": "open"}],
    )
    row = next(r for r in rows if r["framework_id"] == "nist-ai-rmf")
    assert row["evidence_pct"] == 100.0  # Evidence exists; it does not prove a pass.
    assert row["score"] == 0
    assert row["passing_controls"] == 0


def test_ai_posture_separates_pass_fail_and_unevaluated_controls():
    from security_lakehouse.ai_governance import _framework_rows

    rows = _framework_rows(
        controls=[
            {"control_id": "NIST-AI-RMF-GOVERN-1.1", "status": "pass"},
            {"control_id": "NIST-AI-RMF-GOVERN-1.2", "status": "fail"},
        ],
        events=[
            {"control_ids": ["NIST-AI-RMF-GOVERN-1.3"], "status": "observed"},
            {
                "control_ids": ["NIST-AI-RMF-GOVERN-1.1"],
                "status": "pass",
                "event_time": datetime.now(UTC).isoformat(),
                "evidence_ref": "fixture://current",
            },
        ],
    )
    row = next(r for r in rows if r["framework_id"] == "nist-ai-rmf")
    assert row["score"] == 33
    assert row["passing_controls"] == 1
    assert row["failing_controls"] == 1
    assert row["unevaluated_controls"] == 1


def test_ai_frameworks_use_catalog_ids_and_the_safeguard_mapped_count():
    from security_lakehouse.ai_governance import _framework_rows
    from security_lakehouse.safeguards import coverage_by_framework

    rows = {row["framework_id"]: row for row in _framework_rows(controls=[], events=[])}
    coverage = coverage_by_framework()["frameworks"]

    assert set(rows) == {"nist-ai-rmf", "iso-42001-2023", "eu-ai-act-2024-1689"}
    for framework_id, row in rows.items():
        # The same numbers the Frameworks page shows for the pack.
        assert row["requirements"] == coverage[framework_id]["controls"] > 0
        assert row["mapped_requirements"] == coverage[framework_id]["covered"]
        assert row["mapped_pct"] == coverage[framework_id]["coverage_pct"]
        # Nothing evaluated is "not evaluated", not a 0% score.
        assert row["score"] is None


def test_unevaluated_ai_frameworks_do_not_drag_the_governance_score(tmp_path: Path) -> None:
    from security_lakehouse.ai_governance import _framework_score

    rows = [{"score": 90, "controls_with_evidence": 10, "passing_controls": 9}, {"score": None}, {"score": None}]
    assert _framework_score(rows) == 90
    assert _framework_score([{"score": None}]) == 0


def test_inferred_model_inventory_is_not_reported_as_missing(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    _write_jsonl(
        tmp_path / "silver" / "normalized_events.jsonl",
        [
            {
                "event_id": "evt-lineage",
                "event_time": "2026-05-20T13:00:00Z",
                "event_type": "model.lineage",
                "control_ids": [],
                "asset_id": "model:fraud-scorer",
                "asset_owner": "ml-platform",
                "asset_type": "ai_model",
                "environment": "prod",
                "source": "mlflow",
                "status": "observed",
                "severity": "low",
                "severity_score": 10,
                "evidence_ref": "s3://evidence/evt-lineage.json",
                "raw_sha256": "abc",
            }
        ],
    )
    data = build_ai_governance_status(lake=tmp_path)
    assert data["inventory"]["models"] == 1
    assert "model_inventory" not in {gap["id"] for gap in data["gaps"]}
