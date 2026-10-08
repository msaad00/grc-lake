"""V1 audit-log API and event_id semantics."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from security_lakehouse.audit_log import build_audit_log
from security_lakehouse.auth.request_audit import append_request_audit
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_request_audit_assigns_event_id(tmp_path: Path) -> None:
    row = append_request_audit(
        tmp_path,
        method="GET",
        route="/api/v1/healthz",
        status_code=200,
        decision="allow",
        correlation_id="corr-123",
    )
    assert row["event_id"]
    assert row["correlation_id"] == "corr-123"
    entries = build_audit_log(tmp_path, category="request", include_requests=True)
    assert entries[0]["event_id"] == row["event_id"]


def test_audit_log_v1_envelope(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    with app.state.sessionmaker() as session:
        tenant = create_tenant(session, slug="logco", name="Log Co")
        user = create_user(session, tenant_id=tenant.id, email="read@logco.test", role="read_only")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        session.commit()
    resp = client.get("/api/v1/audit-log?limit=10", headers=_bearer(token))
    assert resp.status_code == HTTPStatus.OK
    body = resp.json()
    assert body["meta"]["resource"] == "audit-log"
    assert isinstance(body["data"], list)
    if body["data"]:
        assert "event_id" in body["data"][0]
        assert "occurred_at" in body["data"][0]


def test_build_audit_log_event_ids_unique_per_row(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    append_request_audit(
        tmp_path,
        method="GET",
        route="/a",
        status_code=401,
        decision="deny",
        correlation_id="c1",
    )
    append_request_audit(
        tmp_path,
        method="GET",
        route="/b",
        status_code=200,
        decision="allow",
        correlation_id="c2",
    )
    entries = build_audit_log(tmp_path, category="request", include_requests=True, limit=10)
    ids = {row["event_id"] for row in entries}
    assert len(ids) == len(entries)
