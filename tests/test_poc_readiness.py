"""POC launch readiness surface."""

from __future__ import annotations

import json
from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient  # noqa: E402

from security_lakehouse import api_v1, trust_share  # noqa: E402
from security_lakehouse.db import agent_runs  # noqa: E402
from security_lakehouse.db.base import session_scope  # noqa: E402
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user  # noqa: E402
from security_lakehouse.server_app import create_app  # noqa: E402
from test_api_v1 import _seed_lake  # noqa: E402


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _seed_auth(app, *, tenant_slug: str = "acme") -> dict[str, str]:
    tokens: dict[str, str] = {}
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug=tenant_slug, name="Acme")
        tokens["tenant_id"] = tenant.id
        for role in ("admin", "read_only"):
            user = create_user(session, tenant_id=tenant.id, email=f"{role}@acme.test", role=role)
            _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id, name=f"{role}-key")
            tokens[role] = token
    return tokens


def test_poc_readiness_requires_admin(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    tokens = _seed_auth(app)

    denied = client.get("/api/v1/platform/poc-readiness", headers=_bearer(tokens["read_only"]))
    assert denied.status_code == HTTPStatus.FORBIDDEN

    allowed = client.get("/api/v1/platform/poc-readiness", headers=_bearer(tokens["admin"]))
    assert allowed.status_code == HTTPStatus.OK
    body = allowed.json()
    assert body["meta"]["resource"] == "platform.poc-readiness"
    assert body["data"]["workspace"]["current_role"] == "admin"


def test_poc_readiness_reports_launch_gates_without_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_lake(tmp_path)
    created = trust_share.create_share(
        tmp_path,
        role="auditor",
        expires_in_hours=24,
        created_by="test",
        idempotency_key="poc-readiness-test",
    )
    raw_share_token = created["token"]
    monkeypatch.setenv("GRC_LAKE_PUBLIC_URL", "https://trustops.example.test")
    app = create_app(tmp_path)
    client = TestClient(app)
    tokens = _seed_auth(app, tenant_slug="example")
    with session_scope(app.state.sessionmaker) as session:
        agent_runs.run_and_persist_agent(
            session,
            tenant_id=tokens["tenant_id"],
            lake_dir=tmp_path,
            harness="posture_review",
            objective="review launch posture",
            role="admin",
            created_by="admin@example.test",
            idempotency_key="poc-readiness-agent-review",
        )

    resp = client.get("/api/v1/platform/poc-readiness", headers=_bearer(tokens["admin"]))
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()["data"]
    by_id = {step["id"]: step for step in data["steps"]}

    assert data["public_url"] == "https://trustops.example.test"
    assert by_id["public_url"]["status"] == "ready"
    assert by_id["human_access"]["status"] == "needs_setup"
    assert by_id["headless_access"]["status"] == "ready"
    assert all(str(step["href"] or "/console/").startswith("/console/") for step in data["steps"])
    assert by_id["agent_review"]["status"] == "ready"
    assert data["trust_shares"]["active"] == 1
    assert data["agents"]["completed"] == 1
    assert data["agents"]["runs"] == 1
    assert data["agents"]["latest_run_at"]
    assert raw_share_token not in json.dumps(data, sort_keys=True)
    assert "demo_kit" in data
    assert data["demo_kit"]["public_url"] == "https://trustops.example.test"
    assert any(link["kind"] == "login" for link in data["demo_kit"]["share_links"])
    assert len(data["demo_kit"]["account_linking"]) == 6
    onboarding = data["onboarding"]
    assert onboarding["blocking_total"] >= 3
    assert onboarding["progress_percent"] >= 0
    assert onboarding["current_step_id"]
    assert any(step.get("console_href") == "/connectors?onboarding=1" for step in onboarding["steps"])


def test_poc_readiness_is_in_resource_catalog() -> None:
    resources = {row["resource"]: row for row in api_v1.resource_catalog()}
    assert resources["platform.poc-readiness"]["path"] == "/api/v1/platform/poc-readiness"
    assert resources["platform.poc-readiness"]["scopes"] == ["auth_admin"]


def _local_readiness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    for name in ("GRC_LAKE_PUBLIC_URL", "GRC_LAKE_BASE_URL", "GRC_LAKE_APP_URL"):
        monkeypatch.delenv(name, raising=False)
    _seed_lake(tmp_path)
    app = create_app(tmp_path, require_auth=False)
    client = TestClient(app)
    resp = client.get("/api/v1/platform/poc-readiness")
    assert resp.status_code == HTTPStatus.OK
    return resp.json()["data"]


def test_local_mode_does_not_claim_human_access_ready(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = _local_readiness(tmp_path, monkeypatch)
    human = next(step for step in data["steps"] if step["id"] == "human_access")

    assert data["access"]["require_auth"] is False
    assert human["status"] == "skipped"
    assert human["detail"] == "Local mode — browser sign-in is off"
    assert data["shareable"] is False
    assert data["onboarding"]["completed_blocking"] < data["onboarding"]["blocking_total"]


def test_public_url_step_has_plain_copy_link_and_follows_source_sync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _local_readiness(tmp_path, monkeypatch)
    order = [step["id"] for step in data["steps"]]
    public = next(step for step in data["steps"] if step["id"] == "public_url")

    assert order.index("public_url") > order.index("source_sync")
    assert order[0] != "public_url"
    assert public["status"] == "needs_setup"
    assert public["detail"] == "Set the public URL so invite and share links work"
    assert public["href"] == "/console/deploy/"
    assert "GRC_LAKE_PUBLIC_URL" not in public["detail"]
