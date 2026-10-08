"""Bounded-page contract for the server-mode GRC list endpoints.

The risk register, remediation tasks/evidence-requests/exceptions, tags, and
saved-views list functions used to return every row for a tenant. A tenant with
a large register could exhaust server memory and produce unbounded responses.
These tests pin the fix: the HTTP layer always applies a clamped page window,
while the data-access layer stays unbounded for internal aggregation callers.
"""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from fastapi.testclient import TestClient

from security_lakehouse.db import remediation, risks, tags
from security_lakehouse.db.base import DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, clamp_limit, session_scope
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def env(tmp_path: Path):
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        user = create_user(session, tenant_id=tenant.id, email="contributor@acme.test", role="contributor")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        for i in range(150):
            risks.create_risk(session, tenant_id=tenant.id, title=f"risk-{i:03d}", severity="medium")
            remediation.create_task(session, tenant_id=tenant.id, title=f"task-{i:03d}")
            tags.create_tag(session, tenant_id=tenant.id, name=f"tag-{i:03d}")
        tenant_id = tenant.id
    return app, client, token, tenant_id


# --- clamp helper ------------------------------------------------------------


def test_clamp_limit_bounds() -> None:
    assert clamp_limit(None) == DEFAULT_PAGE_LIMIT
    assert clamp_limit(0) == 1
    assert clamp_limit(-5) == 1
    assert clamp_limit(10) == 10
    assert clamp_limit(10_000_000) == MAX_PAGE_LIMIT
    assert clamp_limit("not-a-number") == DEFAULT_PAGE_LIMIT  # type: ignore[arg-type]


# --- data-access layer stays unbounded for internal callers ------------------


def test_db_layer_unbounded_by_default(env) -> None:
    app, _client, _token, tenant_id = env
    with session_scope(app.state.sessionmaker) as session:
        assert len(risks.list_risks(session, tenant_id=tenant_id)) == 150
        assert len(risks.list_risks(session, tenant_id=tenant_id, limit=25)) == 25
        assert len(risks.list_risks(session, tenant_id=tenant_id, limit=25, offset=140)) == 10


# --- HTTP layer is always bounded --------------------------------------------


def test_risks_endpoint_defaults_to_one_page(env) -> None:
    _app, client, token, _tenant_id = env
    resp = client.get("/api/v1/risks", headers=_bearer(token))
    assert resp.status_code == HTTPStatus.OK
    body = resp.json()
    assert len(body["data"]) == DEFAULT_PAGE_LIMIT
    assert {"count": DEFAULT_PAGE_LIMIT, "limit": DEFAULT_PAGE_LIMIT, "offset": 0}.items() <= body["meta"].items()


def test_risks_endpoint_honours_limit_and_offset(env) -> None:
    _app, client, token, _tenant_id = env
    resp = client.get("/api/v1/risks?limit=20&offset=140", headers=_bearer(token))
    body = resp.json()
    assert len(body["data"]) == 10  # only 10 rows remain past offset 140
    assert body["meta"]["limit"] == 20
    assert body["meta"]["offset"] == 140


def test_oversized_limit_is_capped(env) -> None:
    _app, client, token, _tenant_id = env
    resp = client.get("/api/v1/risks?limit=10000000", headers=_bearer(token))
    body = resp.json()
    assert body["meta"]["limit"] == MAX_PAGE_LIMIT
    assert len(body["data"]) == 150  # capped page is larger than the row count


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/risks",
        "/api/v1/remediation/tasks",
        "/api/v1/tags",
    ],
)
def test_list_endpoints_carry_page_meta(env, path: str) -> None:
    _app, client, token, _tenant_id = env
    body = client.get(path, headers=_bearer(token)).json()
    assert body["meta"]["limit"] == DEFAULT_PAGE_LIMIT
    assert body["meta"]["offset"] == 0
    assert len(body["data"]) == DEFAULT_PAGE_LIMIT
