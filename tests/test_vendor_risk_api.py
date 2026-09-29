"""Vendor-risk questionnaire API (templates + assessments)."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from fastapi.testclient import TestClient  # noqa: E402

from security_lakehouse.db.base import session_scope  # noqa: E402
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user  # noqa: E402
from security_lakehouse.server_app import create_app  # noqa: E402
from test_api_v1 import _seed_lake  # noqa: E402


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def env(tmp_path: Path):
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    tokens: dict[str, str] = {}
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        for role in ("read_only", "security_admin"):
            user = create_user(session, tenant_id=tenant.id, email=f"{role}@acme.test", role=role)
            _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
            tokens[role] = token
    return client, tokens


def test_requires_auth(env) -> None:
    client, _tokens = env
    assert client.get("/api/v1/vendor-assessments").status_code == HTTPStatus.UNAUTHORIZED


def test_list_templates_readable(env) -> None:
    client, tokens = env
    resp = client.get("/api/v1/vendor-questionnaires", headers=_bearer(tokens["read_only"]))
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()["data"]
    template = next(row for row in data if row["template_id"] == "soc2-vendor-standard")
    assert template["mapped_question_count"] == template["question_count"] == 10
    assert template["mapping_status"] == "proposed"
    assert "third-party-risk" in template["risk_domains"]
    assert {"soc2", "iso-27001-2022", "fedramp-moderate"} <= set(template["framework_ids"])
    assert len(template["safeguard_ids"]) >= 7


def test_create_requires_control_manage(env) -> None:
    client, tokens = env
    body = {"vendor_name": "Acme SaaS", "template_id": "soc2-vendor-standard"}
    assert client.post("/api/v1/vendor-assessments", json=body, headers=_bearer(tokens["read_only"])).status_code == (
        HTTPStatus.FORBIDDEN
    )
    resp = client.post("/api/v1/vendor-assessments", json=body, headers=_bearer(tokens["security_admin"]))
    assert resp.status_code == HTTPStatus.CREATED
    assert resp.json()["data"]["status"] == "draft"


def test_assessment_lifecycle(env) -> None:
    client, tokens = env
    admin = _bearer(tokens["security_admin"])

    created = client.post(
        "/api/v1/vendor-assessments",
        json={"vendor_name": "Acme SaaS", "template_id": "soc2-vendor-standard"},
        headers=admin,
    ).json()["data"]
    aid = created["id"]

    detail = client.get(f"/api/v1/vendor-assessments/{aid}", headers=admin).json()["data"]
    assert detail["template"]["template_id"] == "soc2-vendor-standard"

    yes = {
        q["question_id"]: {"answer": "yes"} for section in detail["template"]["sections"] for q in section["questions"]
    }
    saved = client.patch(
        f"/api/v1/vendor-assessments/{aid}",
        json={"responses": yes, "status": "in_review"},
        headers=admin,
    )
    assert saved.status_code == HTTPStatus.OK
    assert saved.json()["data"]["status"] == "in_review"

    scored = client.post(f"/api/v1/vendor-assessments/{aid}/submit", headers=admin)
    assert scored.status_code == HTTPStatus.OK
    body = scored.json()["data"]
    assert body["status"] == "completed"
    assert body["score"] == 100.0
    assert body["risk_level"] == "low"


def test_unknown_assessment_returns_404(env) -> None:
    client, tokens = env
    admin = _bearer(tokens["security_admin"])
    assert client.get("/api/v1/vendor-assessments/nope", headers=admin).status_code == HTTPStatus.NOT_FOUND


def test_list_filters_by_status(env) -> None:
    client, tokens = env
    admin = _bearer(tokens["security_admin"])
    body = {"vendor_name": "Acme SaaS", "template_id": "soc2-vendor-standard"}
    draft = client.post("/api/v1/vendor-assessments", json=body, headers=admin).json()["data"]
    reviewing = client.post("/api/v1/vendor-assessments", json=body, headers=admin).json()["data"]
    client.patch(f"/api/v1/vendor-assessments/{reviewing['id']}", json={"status": "in_review"}, headers=admin)

    resp = client.get("/api/v1/vendor-assessments?status=draft", headers=admin)
    assert resp.status_code == HTTPStatus.OK
    assert [row["id"] for row in resp.json()["data"]] == [draft["id"]]
    in_review = client.get("/api/v1/vendor-assessments?status=in_review", headers=admin).json()["data"]
    assert [row["id"] for row in in_review] == [reviewing["id"]]
