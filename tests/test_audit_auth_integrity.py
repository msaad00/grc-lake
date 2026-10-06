"""Production startup and authenticated snapshot-integrity boundaries."""

from argparse import Namespace

import pytest
from fastapi.testclient import TestClient

from security_lakehouse import api_v1, cli
from security_lakehouse.assessment import write_assessment_snapshot
from security_lakehouse.auth.rbac import Identity
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake


@pytest.mark.parametrize("environment", ["production", "prod", "staging", " Production "])
@pytest.mark.parametrize("entry", ["argument", "environment", "cli"])
def test_production_rejects_all_no_auth_entries(tmp_path, monkeypatch, environment, entry):
    monkeypatch.setenv("TRUSTOPS_ENV", environment)
    monkeypatch.delenv("TRUSTOPS_ALLOW_INSECURE_NO_AUTH", raising=False)
    if entry == "environment":
        monkeypatch.setenv("TRUSTOPS_ALLOW_INSECURE_NO_AUTH", "true")
    monkeypatch.setattr("uvicorn.run", lambda *args, **kwargs: None)
    with pytest.raises(RuntimeError, match="forbidden"):
        if entry == "cli":
            cli._serve(Namespace(server=True, allow_insecure_no_auth=True, lake=tmp_path, host="127.0.0.1", port=0))
        else:
            create_app(tmp_path, require_auth=entry != "argument")
    assert not (tmp_path / "gold").exists()


@pytest.mark.parametrize(
    "method,expected",
    [("session:oidc", True), ("session:saml", True), ("insecure", False), ("api_key", False), ("unknown", False)],
)
def test_only_authenticated_sessions_are_interactive(method, expected):
    assert (
        Identity("u", "t", "u@example.test", "admin", frozenset(), auth_method=method).is_interactive_session
        is expected
    )


def test_development_insecure_cannot_decide_mapping_review(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTOPS_ENV", "development")
    from test_mapping_review_api import _proposed_items

    client = TestClient(create_app(tmp_path, require_auth=False))
    response = client.post(
        "/api/v1/mapping-reviews/decisions",
        json={"decision": "approve", "rationale": "Reviewed", "items": _proposed_items(1)},
    )
    assert response.status_code == 403


def test_integrity_route_is_authenticated_tenant_scoped_and_matches_local(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTOPS_ENV", "production")
    monkeypatch.delenv("TRUSTOPS_ALLOW_INSECURE_NO_AUTH", raising=False)
    app = create_app(tmp_path)
    tokens = []
    with session_scope(app.state.sessionmaker) as session:
        for slug in ("first", "second"):
            tenant = create_tenant(session, slug=slug, name=slug)
            user = create_user(session, tenant_id=tenant.id, email=f"{slug}@example.test", role="read_only")
            _, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id, name="reader")
            tokens.append((tenant.id, token))
    client = TestClient(app)
    route = "/api/v1/snapshots/integrity"
    assert client.get(route).status_code == 401
    first_lake = tmp_path / "tenants" / tokens[0][0]
    first_lake.mkdir(parents=True)
    _seed_lake(first_lake)
    snapshot = write_assessment_snapshot(first_lake)
    for tenant_id, token in tokens:
        response = client.get(route, headers={"Authorization": f"Bearer {token}"})
        local_status, local = api_v1.handle_get(route, {}, tmp_path / "tenants" / tenant_id)
        assert response.status_code == local_status == 200
        assert response.json() == local
        assert response.json()["data"]["length"] == (1 if tenant_id == tokens[0][0] else 0)
    snapshot.write_text("{}")
    response = client.get(route, headers={"Authorization": f"Bearer {tokens[0][1]}"})
    assert response.status_code == 200
    assert response.json()["data"]["ok"] is False
