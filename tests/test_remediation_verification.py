"""Real sealed-generation retests, including stale, foreign, and tampered evidence."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from security_lakehouse.db import remediation
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_tenant
from security_lakehouse.io import read_jsonl
from security_lakehouse.pipeline import run_pipeline
from security_lakehouse.remediation_verification import verify_task
from security_lakehouse.server_app import create_app


@pytest.mark.parametrize("owner_alias", ["email", "id", "external"])
def test_owner_reassignment_cannot_erase_independence_boundary(tmp_path, owner_alias):
    from security_lakehouse.db.repository import create_user

    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="reassignment", name="Reassignment")
        user = create_user(session, tenant_id=tenant.id, email="implementer@example.test", role="security_admin")
        user.scim_external_id = "provider-implementer"
        session.flush()
        owner = {"email": user.email, "id": user.id, "external": user.scim_external_id}[owner_alias]
        task = remediation.create_task(session, tenant_id=tenant.id, title="Fix", control_id="SOC2-CC6.1", owner=owner)
        remediation.update_task(
            session, tenant_id=tenant.id, task_id=task.id, changes={"owner": "replacement@example.test"}
        )
        with pytest.raises(ValueError, match="independent"):
            verify_task(
                session, tmp_path, tenant_id=tenant.id, task_id=task.id, reviewer_id=user.id, reviewer=user.email
            )


@pytest.mark.parametrize("failure", [None, "old", "future", "failed", "foreign", "tampered", "concurrent"])
def test_only_fresh_passing_owned_evidence_can_resolve(tmp_path, failure):
    app = create_app(tmp_path)
    now = datetime.now(UTC)
    raw = json.loads(
        (Path(__file__).resolve().parents[1] / "data/raw/security_events.jsonl").read_text().splitlines()[0]
    )
    raw["status"] = "pass" if failure != "failed" else "fail"
    raw["severity"] = "info"
    observed = now - timedelta(minutes=1)
    if failure == "old":
        observed = now - timedelta(days=1)
    if failure == "future":
        observed = now + timedelta(hours=1)
    raw["event_time"] = observed.isoformat()
    raw["evidence"]["collected_at"] = observed.isoformat()
    source = tmp_path / "input.jsonl"
    source.write_text(json.dumps(raw) + "\n")
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="test", name="Test")
        run_pipeline(source, tmp_path, tenant_id=tenant.id if failure != "foreign" else "another-tenant")
        tests = read_jsonl(tmp_path / "gold/control_tests.jsonl")
        selected = next((row for row in tests if row["result"] == "pass"), tests[0])
        task = remediation.create_task(
            session, tenant_id=tenant.id, title="Remediate", control_id=selected["control_id"]
        )
        task.created_at = now - timedelta(minutes=5)
        session.flush()
        if failure == "tampered":
            (tmp_path / "gold/control_tests.jsonl").write_text("{}\n")

        def verify():
            return verify_task(
                session,
                tmp_path,
                tenant_id=tenant.id,
                task_id=task.id,
                reviewer_id="reviewer",
                reviewer="reviewer@example.test",
                now=now,
            )

        if failure == "concurrent":
            # Keep this ORM instance stale while another transaction records a retest.
            session.commit()
            with session_scope(app.state.sessionmaker) as other:
                verify_task(
                    other,
                    tmp_path,
                    tenant_id=tenant.id,
                    task_id=task.id,
                    reviewer_id="first-reviewer",
                    reviewer="first@example.test",
                    now=now,
                )
            with pytest.raises(ValueError, match="changed"):
                verify()
            session.rollback()
            session.refresh(task)
            assert json.loads(task.verification_history)[0]["reviewer_id"] == "first-reviewer"
        elif failure:
            with pytest.raises((ValueError, KeyError)):
                verify()
            assert task.status == "open"
            assert not json.loads(task.verification_history)
        else:
            assert selected["result"] == "pass"
            verified = verify()
            assert verified.status == "resolved"
            proof = json.loads(verified.verification_history)[0]
            assert proof["control_id"] == task.control_id
            assert proof["evidence"][0]["raw_sha256"]
            assert proof["generation"]["manifest_sha256"]
            remediation.update_task(session, tenant_id=tenant.id, task_id=task.id, changes={"status": "open"})
            assert json.loads(task.verification_history) == [proof]


def test_authenticated_http_retest_binds_reviewer_and_rejects_claims(tmp_path, monkeypatch):
    from test_agent_decision_authority import human

    monkeypatch.setenv("TRUSTOPS_COOKIE_SIGNING_KEY", "local-test-retest-signing-key")
    from fastapi.testclient import TestClient

    from security_lakehouse.db.models import RemediationTask
    from security_lakehouse.db.repository import create_api_key, create_user

    app = create_app(tmp_path)
    client = TestClient(app)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="test", name="Test")
        reviewer = create_user(session, tenant_id=tenant.id, email="reviewer@example.test", role="security_admin")
        _, token = create_api_key(session, tenant_id=tenant.id, user_id=reviewer.id)
        contributor = create_user(session, tenant_id=tenant.id, email="owner@example.test", role="contributor")
        _, owner_token = create_api_key(session, tenant_id=tenant.id, user_id=contributor.id)
    headers = human(app, token)
    raw = json.loads(
        (Path(__file__).resolve().parents[1] / "data/raw/security_events.jsonl").read_text().splitlines()[0]
    )
    now = datetime.now(UTC)
    raw.update(status="pass", severity="info", event_time=(now - timedelta(seconds=1)).isoformat())
    raw["evidence"]["collected_at"] = raw["event_time"]
    source = tmp_path / "input.jsonl"
    source.write_text(json.dumps(raw) + "\n")
    run_pipeline(source, tmp_path, tenant_id=tenant.id)
    control = next(
        row["control_id"] for row in read_jsonl(tmp_path / "gold/control_tests.jsonl") if row["result"] == "pass"
    )
    task = client.post(
        "/api/v1/remediation/tasks",
        json={"title": "Fix", "control_id": control},
        headers={"Authorization": f"Bearer {owner_token}"},
    ).json()["data"]
    url = f"/api/v1/remediation/tasks/{task['id']}/verify"
    assert client.post(url, json={}, headers={"Authorization": f"Bearer {owner_token}"}).status_code == 403
    assert client.post(url, json={"reviewer_id": "forged"}, headers=headers).status_code == 422
    assert client.post(url, json={"resolution_note": "not evidence"}, headers=headers).status_code == 400
    current = client.get(url.removesuffix("/verify"), headers=headers).json()["data"]
    assert current["status"] == "open" and current["resolution_note"] == ""
    with session_scope(app.state.sessionmaker) as session:
        session.get(RemediationTask, task["id"]).created_at = now - timedelta(minutes=5)
    response = client.post(url, json={"resolution_note": "Configuration corrected"}, headers=headers)
    assert response.status_code == 200
    receipt = response.json()["data"]["verification_history"][0]
    assert receipt["reviewer_id"] == reviewer.id
    assert receipt["tenant_id"] == tenant.id
