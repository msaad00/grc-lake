"""Independent human authority and atomic agent-decision execution."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from security_lakehouse.auth.sessions import SESSION_COOKIE, encode_session_cookie
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_user_session, resolve_api_key
from test_agent_runs_api import _bearer, _posture_run
from test_agent_runs_api import env as env


def human(app, token):
    with session_scope(app.state.sessionmaker) as session:
        key = resolve_api_key(session, token)
        _, value = create_user_session(session, tenant_id=key.tenant_id, user_id=key.user_id, idp="oidc")
    return {"Cookie": f"{SESSION_COOKIE}={encode_session_cookie(value)}"}


def test_agent_creator_and_machine_credentials_cannot_approve(env):
    app, client, tokens = env
    run_id = _posture_run(client, tokens["contributor"])
    url = f"/api/v1/agent-runs/{run_id}/decisions/0/approve"
    assert client.post(url, headers=_bearer(tokens["contributor"])).status_code == 403
    assert client.post(url, headers=human(app, tokens["contributor"])).status_code == 403
    assert client.post(url, headers=_bearer(tokens["security_admin"])).status_code == 403
    assert client.post(url, headers=human(app, tokens["security_admin"])).status_code == 200


def test_simultaneous_agent_approvals_execute_once(env, monkeypatch):
    from security_lakehouse import server_app

    app, client, tokens = env
    run_id = _posture_run(client, tokens["contributor"])
    headers = human(app, tokens["security_admin"])
    execute = server_app._execute_agent_decision
    calls = []
    lock = threading.Lock()
    start = threading.Barrier(6)

    def observed(*args, **kwargs):
        with lock:
            calls.append(1)
        time.sleep(0.1)
        return execute(*args, **kwargs)

    monkeypatch.setattr(server_app, "_execute_agent_decision", observed)

    def approve(_):
        start.wait(timeout=10)
        with TestClient(app, raise_server_exceptions=False) as concurrent_client:
            return concurrent_client.post(
                f"/api/v1/agent-runs/{run_id}/decisions/0/approve", headers=headers
            ).status_code

    with ThreadPoolExecutor(max_workers=6) as executor:
        statuses = list(executor.map(approve, range(6)))
    assert calls == [1], statuses
    assert 200 in statuses
    assert set(statuses) <= {200, 409}
    requests = client.get("/api/v1/remediation/evidence-requests", headers=_bearer(tokens["contributor"]))
    assert len(requests.json()["data"]) == 1


def test_interrupted_agent_execution_requires_reconciliation(env, monkeypatch):
    from security_lakehouse import server_app

    app, client, tokens = env
    run_id = _posture_run(client, tokens["contributor"])
    headers = human(app, tokens["security_admin"])
    calls = []

    def crash(*args, **kwargs):
        calls.append(1)
        raise RuntimeError("simulated interrupted execution")

    monkeypatch.setattr(server_app, "_execute_agent_decision", crash)
    with TestClient(app, raise_server_exceptions=False) as crash_client:
        url = f"/api/v1/agent-runs/{run_id}/decisions/0"
        assert crash_client.post(url + "/approve", headers=headers).status_code == 500
        assert crash_client.post(url + "/approve", headers=headers).status_code == 409
        assert crash_client.post(url + "/reject", json={"reason": "late"}, headers=headers).status_code == 409
    assert calls == [1]


def _claim_in_process(args):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from security_lakehouse.db.agent_runs import DecisionConflict, claim_decision
    from security_lakehouse.db.models import AgentRun

    url, run_id, rejection = args
    engine = create_engine(url)
    try:
        with Session(engine) as session:
            row = session.get(AgentRun, run_id)
            try:
                claim_decision(session, row, decision_index=0, actor="reviewer", rejection_reason=rejection)
                return "claimed"
            except DecisionConflict:
                return "conflict"
    finally:
        engine.dispose()


def _database_run(url):
    import json

    from alembic import command
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from security_lakehouse.db.migrate import _config
    from security_lakehouse.db.models import AgentRun
    from security_lakehouse.db.repository import create_tenant

    command.upgrade(_config(url), "head")
    engine = create_engine(url)
    with Session(engine) as session:
        tenant = create_tenant(session, slug="race", name="Race")
        row = AgentRun(
            tenant_id=tenant.id,
            harness="posture_review",
            role="contributor",
            input_hash="a" * 64,
            decisions_json=json.dumps([{"action": "create_evidence_request", "status": "proposed"}]),
            state_json="{}",
            created_by_id="creator",
        )
        session.add(row)
        session.commit()
        run_id = row.id
    return engine, run_id


from test_migration_portability import migration_url as migration_url  # noqa: E402


def test_agent_claim_is_atomic_across_processes_and_rejection(migration_url):
    import multiprocessing

    engine, run_id = _database_run(migration_url)
    engine.dispose()
    with multiprocessing.get_context("spawn").Pool(4) as pool:
        outcomes = pool.map(
            _claim_in_process,
            [(migration_url, run_id, None if i % 2 else "declined") for i in range(8)],
        )
    assert outcomes.count("claimed") == 1


def test_agent_claim_rejects_changed_reviewed_content(migration_url):
    import json

    import pytest
    from sqlalchemy.orm import Session

    from security_lakehouse.db.agent_runs import DecisionConflict, claim_decision
    from security_lakehouse.db.models import AgentRun

    engine, run_id = _database_run(migration_url)
    try:
        with Session(engine) as reviewer:
            reviewed = reviewer.get(AgentRun, run_id)
            with Session(engine) as writer:
                changed = writer.get(AgentRun, run_id)
                proposal = json.loads(changed.decisions_json)
                proposal[0]["payload"] = {"control_id": "different-reviewed-content"}
                changed.decisions_json = json.dumps(proposal)
                writer.commit()
            with pytest.raises(DecisionConflict):
                claim_decision(reviewer, reviewed, decision_index=0, actor="reviewer")
    finally:
        engine.dispose()
