"""Absent or unknown evidence cannot imply complete passing coverage."""

import pytest
from fastapi.testclient import TestClient

from security_lakehouse import server_app, trust_share
from security_lakehouse.db import metrics
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_tenant
from security_lakehouse.io import write_jsonl
from security_lakehouse.sprs import build_sprs_report
from test_approval_authority import credentials as credentials_fixture

credentials = credentials_fixture


@pytest.mark.parametrize("result", [None, "not_evaluated", "observed", "stale"])
def test_sprs_unknown_is_not_met(tmp_path, result):
    if result:
        write_jsonl(
            tmp_path / "gold/control_tests.jsonl",
            [{"framework_id": "cmmc-2-level2", "control_id": "CMMC-3.1.1", "result": result}],
        )
    report = build_sprs_report(tmp_path)
    assert report["score"] is None
    assert report["requirements_met"] == 0
    assert report["requirements_not_evaluated"] == report["requirements_total"]


def test_sprs_duplicate_failure_overrides_pass(tmp_path):
    write_jsonl(
        tmp_path / "gold/control_tests.jsonl",
        [
            {"framework_id": "cmmc-2-level2", "control_id": "CMMC-3.1.1", "result": result}
            for result in ("pass", "fail", "pass")
        ],
    )
    report = build_sprs_report(tmp_path)
    assert report["requirements_met"] == 0
    assert report["requirements_unmet"] == 1


@pytest.mark.parametrize("total", [0, 3])
def test_metric_pass_rate_requires_explicit_passes(tmp_path, monkeypatch, total):
    app = server_app.create_app(tmp_path)
    monkeypatch.setattr(
        "security_lakehouse.assessment.build_current_posture",
        lambda *a, **k: {
            "posture": {"control_count": total},
            "frameworks": [
                {
                    "control_count": total,
                    "failing_control_count": 0,
                    "passing_control_count": 0,
                    "not_evaluated_control_count": total,
                }
            ],
        },
    )
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="a", name="A")
        point = metrics.capture_metric_point(session, tenant_id=tenant.id, lake_dir=tmp_path)
        assert point.control_pass_rate == 0


def test_public_share_issuer_is_authenticated(credentials):
    app, token, *_ = credentials
    client = TestClient(app)
    share = client.post(
        "/api/v1/trust-shares",
        headers={"Authorization": f"Bearer {token}"},
        json={"role": "auditor", "created_by": "forged@example.test"},
    ).json()["data"]
    assert share["created_by"] == "admin@example.test"
    assert client.get("/api/public/trust/" + share["token"]).json()["issued_by"] == "admin@example.test"


def test_framework_share_does_not_leak_other_frameworks_or_claim_full_coverage(tmp_path, monkeypatch):
    monkeypatch.setattr(
        server_app,
        "build_current_posture",
        lambda lake: {
            "posture": {"score": 99, "state": "ready", "framework_count": 2, "control_count": 2},
            "frameworks": [
                {
                    "framework": "SOC 2",
                    "score": 100,
                    "state": "ready",
                    "control_count": 1,
                    "not_evaluated_control_count": 0,
                    "passing_control_count": 1,
                },
                {"framework": "Other private program", "score": 98, "state": "ready", "control_count": 1},
            ],
        },
    )
    share = {"scope": "posture_framework", "framework_id": "soc2"}
    result = server_app._public_trust_summary(tmp_path, share)
    assert len(result["frameworks"]) == result["posture"]["framework_count"] == 1
    assert result["posture"]["control_count"] == 1
    framework = result["frameworks"][0]
    assert framework["state"] == "partial_evidence"
    assert framework["catalog_control_count"] == 61
    assert framework["evaluated_control_count"] == 1
    assert framework["coverage_ratio"] < 1


@pytest.mark.parametrize("framework", [None, "unknown-framework"])
def test_framework_share_requires_known_framework(tmp_path, framework):
    with pytest.raises(ValueError, match="framework"):
        trust_share.create_share(tmp_path, role="auditor", scope="posture_framework", framework_id=framework)


def test_sprs_complete_population_retains_weighted_score(tmp_path):
    from security_lakehouse.sprs import _cmmc_sprs_metadata

    write_jsonl(
        tmp_path / "gold/control_tests.jsonl",
        [
            {"framework_id": "cmmc-2-level2", "control_id": "CMMC-" + key, "result": "pass"}
            for key in _cmmc_sprs_metadata()
        ],
    )
    report = build_sprs_report(tmp_path)
    assert report["score"] == 110
    assert report["requirements_met"] == 110
    assert report["requirements_not_evaluated"] == 0
    assert report["assessment_complete"] is True
