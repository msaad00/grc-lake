"""Production SCIM 2.0: per-tenant tokens, SCIM wire format, user lifecycle, groups."""

from __future__ import annotations

import json
from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from security_lakehouse.db.base import session_scope  # noqa: E402
from security_lakehouse.db.models import User  # noqa: E402
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user  # noqa: E402
from security_lakehouse.server_app import create_app  # noqa: E402
from test_api_v1 import _seed_lake  # noqa: E402

SCIM = "/api/v1/scim/v2"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GRC_LAKE_COMMERCIAL_HOSTED", "1")
    monkeypatch.setenv("GRC_LAKE_SCIM_ENABLED", "1")
    monkeypatch.delenv("GRC_LAKE_SCIM_BEARER_TOKEN", raising=False)
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    client = TestClient(app)
    keys: dict[str, str] = {}
    with session_scope(app.state.sessionmaker) as session:
        for slug in ("acme", "globex"):
            tenant = create_tenant(session, slug=slug, name=slug.title())
            for role in ("read_only", "admin"):
                user = create_user(session, tenant_id=tenant.id, email=f"{role}@{slug}.test", role=role)
                _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
                keys[f"{slug}:{role}"] = token
    return client, keys, app


def _scim_token(client: TestClient, admin_key: str, name: str = "okta") -> str:
    created = client.post("/api/v1/platform/scim/tokens", json={"name": name}, headers=_bearer(admin_key))
    assert created.status_code == HTTPStatus.CREATED, created.text
    return created.json()["data"]["token"]


def _create_user(client: TestClient, token: str, email: str, **extra: object) -> dict:
    resp = client.post(
        f"{SCIM}/Users", headers=_bearer(token), json={"schemas": [USER_SCHEMA], "userName": email, **extra}
    )
    assert resp.status_code == HTTPStatus.CREATED, resp.text
    return resp.json()


# --- tokens -----------------------------------------------------------------


def test_admin_manages_hashed_per_tenant_tokens(env) -> None:
    client, keys, _app = env
    resp = client.post("/api/v1/platform/scim/tokens", json={"name": "x"}, headers=_bearer(keys["acme:read_only"]))
    assert resp.status_code == HTTPStatus.FORBIDDEN
    created = client.post("/api/v1/platform/scim/tokens", json={"name": "okta"}, headers=_bearer(keys["acme:admin"]))
    body = created.json()["data"]
    assert body["token"].startswith("tscim_")
    assert body["token_prefix"] == body["token"][:12]

    listed = client.get("/api/v1/platform/scim/tokens", headers=_bearer(keys["acme:admin"])).json()["data"]
    assert [row["name"] for row in listed] == ["okta"]
    assert "token" not in listed[0] and "token_hash" not in listed[0]
    assert body["token"] not in json.dumps(listed)

    assert client.get(f"{SCIM}/Users", headers=_bearer(body["token"])).status_code == HTTPStatus.OK
    revoked = client.delete(f"/api/v1/platform/scim/tokens/{body['id']}", headers=_bearer(keys["acme:admin"]))
    assert revoked.status_code == HTTPStatus.NO_CONTENT
    assert client.get(f"{SCIM}/Users", headers=_bearer(body["token"])).status_code == HTTPStatus.UNAUTHORIZED


def test_rotation_keeps_both_tokens_valid_until_revoke(env) -> None:
    client, keys, _app = env
    old = _scim_token(client, keys["acme:admin"], "old")
    new = _scim_token(client, keys["acme:admin"], "new")
    assert client.get(f"{SCIM}/Users", headers=_bearer(old)).status_code == HTTPStatus.OK
    assert client.get(f"{SCIM}/Users", headers=_bearer(new)).status_code == HTTPStatus.OK


def test_token_scopes_every_operation_to_its_own_tenant(env) -> None:
    client, keys, _app = env
    acme = _scim_token(client, keys["acme:admin"])
    globex = _scim_token(client, keys["globex:admin"])
    user = _create_user(client, acme, "shared@example.com")

    listed = client.get(f"{SCIM}/Users", headers=_bearer(globex)).json()
    assert all(r["userName"].endswith("@globex.test") for r in listed["Resources"])
    assert client.get(f"{SCIM}/Users/{user['id']}", headers=_bearer(globex)).status_code == HTTPStatus.NOT_FOUND
    resp = client.delete(f"{SCIM}/Users/{user['id']}", headers=_bearer(globex))
    assert resp.status_code == HTTPStatus.NOT_FOUND
    # The same userName can exist independently in another tenant.
    _create_user(client, globex, "shared@example.com")


def test_admin_token_management_is_tenant_scoped(env) -> None:
    client, keys, _app = env
    acme = client.post("/api/v1/platform/scim/tokens", json={"name": "a"}, headers=_bearer(keys["acme:admin"]))
    token_id = acme.json()["data"]["id"]
    assert client.get("/api/v1/platform/scim/tokens", headers=_bearer(keys["globex:admin"])).json()["data"] == []
    resp = client.delete(f"/api/v1/platform/scim/tokens/{token_id}", headers=_bearer(keys["globex:admin"]))
    assert resp.status_code == HTTPStatus.NOT_FOUND


def test_bad_or_missing_bearer_is_a_scim_401(env) -> None:
    client, _keys, _app = env
    resp = client.get(f"{SCIM}/Users", headers=_bearer("tscim_wrong"))
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.headers["content-type"].startswith("application/scim+json")
    assert resp.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert resp.json()["status"] == "401"


def test_deprecated_env_bearer_still_resolves_the_env_tenant(env, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _keys, _app = env
    monkeypatch.setenv("GRC_LAKE_SCIM_BEARER_TOKEN", "legacy-token")
    monkeypatch.setenv("GRC_LAKE_SCIM_TENANT_SLUG", "acme")
    listed = client.get(f"{SCIM}/Users", headers=_bearer("legacy-token")).json()
    assert {r["userName"] for r in listed["Resources"]} >= {"admin@acme.test"}


# --- wire format + users ----------------------------------------------------


def test_responses_are_raw_scim_json(env) -> None:
    client, keys, _app = env
    token = _scim_token(client, keys["acme:admin"])
    resp = client.get(f"{SCIM}/Users", headers=_bearer(token))
    assert resp.headers["content-type"].startswith("application/scim+json")
    body = resp.json()
    assert "data" not in body
    assert body["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    config = client.get(f"{SCIM}/ServiceProviderConfig").json()
    assert config["patch"]["supported"] is True
    assert config["filter"]["supported"] is True
    assert config["bulk"]["supported"] is False


def test_filter_by_username_and_external_id(env) -> None:
    client, keys, _app = env
    token = _scim_token(client, keys["acme:admin"])
    user = _create_user(client, token, "Ada@Acme.test", externalId="okta-00u1")
    by_name = client.get(f'{SCIM}/Users?filter=userName eq "ada@acme.test"', headers=_bearer(token)).json()
    assert [r["id"] for r in by_name["Resources"]] == [user["id"]]
    by_ext = client.get(f'{SCIM}/Users?filter=externalId eq "okta-00u1"', headers=_bearer(token)).json()
    assert by_ext["totalResults"] == 1
    none = client.get(f'{SCIM}/Users?filter=userName eq "nobody@acme.test"', headers=_bearer(token)).json()
    assert none["totalResults"] == 0 and none["Resources"] == []
    bad = client.get(f'{SCIM}/Users?filter=userName co "a"', headers=_bearer(token))
    assert bad.status_code == HTTPStatus.BAD_REQUEST
    assert bad.json()["scimType"] == "invalidFilter"


def test_duplicate_username_is_a_409_uniqueness_error(env) -> None:
    client, keys, _app = env
    token = _scim_token(client, keys["acme:admin"])
    _create_user(client, token, "dup@acme.test")
    resp = client.post(
        f"{SCIM}/Users", headers=_bearer(token), json={"schemas": [USER_SCHEMA], "userName": "dup@acme.test"}
    )
    assert resp.status_code == HTTPStatus.CONFLICT
    assert resp.json()["scimType"] == "uniqueness"


def test_put_replaces_and_patch_accepts_okta_and_entra_shapes(env) -> None:
    client, keys, _app = env
    token = _scim_token(client, keys["acme:admin"])
    user = _create_user(client, token, "grace@acme.test", name={"givenName": "Grace", "familyName": "H"})
    assert user["displayName"] == "Grace H"

    put = client.put(
        f"{SCIM}/Users/{user['id']}",
        headers=_bearer(token),
        json={"schemas": [USER_SCHEMA], "userName": "grace@acme.test", "displayName": "Grace Hopper", "active": True},
    ).json()
    assert put["displayName"] == "Grace Hopper"

    okta = client.patch(
        f"{SCIM}/Users/{user['id']}",
        headers=_bearer(token),
        json={"schemas": [PATCH_SCHEMA], "Operations": [{"op": "replace", "value": {"active": False}}]},
    ).json()
    assert okta["active"] is False
    entra = client.patch(
        f"{SCIM}/Users/{user['id']}",
        headers=_bearer(token),
        json={
            "schemas": [PATCH_SCHEMA],
            "Operations": [
                {"op": "Replace", "path": "active", "value": "True"},
                {"op": "Replace", "path": "displayName", "value": "G. Hopper"},
                {"op": "Add", "path": "externalId", "value": "entra-9"},
            ],
        },
    ).json()
    assert (entra["active"], entra["displayName"], entra["externalId"]) == (True, "G. Hopper", "entra-9")


def test_delete_is_a_soft_delete_that_hides_the_user_and_can_be_reprovisioned(env) -> None:
    client, keys, app = env
    token = _scim_token(client, keys["acme:admin"])
    user = _create_user(client, token, "leaver@acme.test")

    resp = client.delete(f"{SCIM}/Users/{user['id']}", headers=_bearer(token))

    assert resp.status_code == HTTPStatus.NO_CONTENT
    assert client.get(f"{SCIM}/Users/{user['id']}", headers=_bearer(token)).status_code == HTTPStatus.NOT_FOUND
    listed = client.get(f'{SCIM}/Users?filter=userName eq "leaver@acme.test"', headers=_bearer(token)).json()
    assert listed["totalResults"] == 0
    with session_scope(app.state.sessionmaker) as session:
        row = session.get(User, user["id"])
        assert row is not None and row.is_active is False  # kept for the audit trail

    again = _create_user(client, token, "leaver@acme.test")
    assert again["id"] == user["id"] and again["active"] is True


# --- groups -----------------------------------------------------------------


def test_group_membership_drives_role_through_the_role_map(env, monkeypatch: pytest.MonkeyPatch) -> None:
    client, keys, app = env
    monkeypatch.setenv(
        "GRC_LAKE_SCIM_ROLE_MAP", json.dumps({"GRC Lake Admins": "admin", "GRC Lake Auditors": "auditor"})
    )
    token = _scim_token(client, keys["acme:admin"])
    user = _create_user(client, token, "ops@acme.test")

    group = client.post(
        f"{SCIM}/Groups",
        headers=_bearer(token),
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "GRC Lake Admins",
            "members": [{"value": user["id"]}],
        },
    )
    assert group.status_code == HTTPStatus.CREATED
    group_id = group.json()["id"]
    assert client.get(f"{SCIM}/Users/{user['id']}", headers=_bearer(token)).json()["trustopsRole"] == "admin"
    found = client.get(f'{SCIM}/Groups?filter=displayName eq "GRC Lake Admins"', headers=_bearer(token)).json()
    assert [g["id"] for g in found["Resources"]] == [group_id]

    removed = client.patch(
        f"{SCIM}/Groups/{group_id}",
        headers=_bearer(token),
        json={
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "remove", "path": f'members[value eq "{user["id"]}"]'}],
        },
    )
    assert removed.status_code == HTTPStatus.OK
    assert client.get(f"{SCIM}/Users/{user['id']}", headers=_bearer(token)).json()["trustopsRole"] == "read_only"

    client.patch(
        f"{SCIM}/Groups/{group_id}",
        headers=_bearer(token),
        json={
            "schemas": [PATCH_SCHEMA],
            "Operations": [{"op": "add", "path": "members", "value": [{"value": user["id"]}]}],
        },
    )
    assert client.get(f"{SCIM}/Users/{user['id']}", headers=_bearer(token)).json()["trustopsRole"] == "admin"
    resp = client.delete(f"{SCIM}/Groups/{group_id}", headers=_bearer(token))
    assert resp.status_code == HTTPStatus.NO_CONTENT
    with session_scope(app.state.sessionmaker) as session:
        assert session.scalars(select(User.role).where(User.id == user["id"])).one() == "read_only"


def test_groups_do_not_touch_roles_without_a_role_map(env) -> None:
    client, keys, _app = env
    token = _scim_token(client, keys["acme:admin"])
    user = _create_user(client, token, "keep@acme.test", trustopsRole="contributor")
    client.post(
        f"{SCIM}/Groups",
        headers=_bearer(token),
        json={"displayName": "Anything", "members": [{"value": user["id"]}]},
    )
    assert client.get(f"{SCIM}/Users/{user['id']}", headers=_bearer(token)).json()["trustopsRole"] == "contributor"


def test_group_members_must_belong_to_the_token_tenant(env) -> None:
    client, keys, _app = env
    acme = _scim_token(client, keys["acme:admin"])
    globex = _scim_token(client, keys["globex:admin"])
    outsider = _create_user(client, globex, "outsider@globex.test")
    resp = client.post(
        f"{SCIM}/Groups", headers=_bearer(acme), json={"displayName": "G", "members": [{"value": outsider["id"]}]}
    )
    assert resp.status_code == HTTPStatus.BAD_REQUEST


def test_disabled_returns_501(env, monkeypatch: pytest.MonkeyPatch) -> None:
    client, keys, _app = env
    monkeypatch.setenv("GRC_LAKE_SCIM_ENABLED", "0")
    assert client.get(f"{SCIM}/Users", headers=_bearer("x")).status_code == HTTPStatus.NOT_IMPLEMENTED
    assert client.get(f"{SCIM}/Groups", headers=_bearer("x")).status_code == HTTPStatus.NOT_IMPLEMENTED
    resp = client.post("/api/v1/platform/scim/tokens", json={"name": "x"}, headers=_bearer(keys["acme:admin"]))
    assert resp.status_code == HTTPStatus.NOT_IMPLEMENTED
    listed = client.get("/api/v1/platform/scim/tokens", headers=_bearer(keys["acme:admin"]))
    assert listed.status_code == HTTPStatus.NOT_IMPLEMENTED


def test_scim_migration_round_trips(tmp_path: Path) -> None:
    from alembic import command
    from sqlalchemy import inspect

    from security_lakehouse.db import migrate
    from security_lakehouse.db.base import create_engine_for, database_url

    migrate.upgrade(tmp_path)
    tables = set(inspect(create_engine_for(tmp_path)).get_table_names())
    assert {"scim_tokens", "scim_groups", "scim_group_members"} <= tables
    cfg = migrate._config(database_url(tmp_path))
    command.downgrade(cfg, "0016_webhooks")
    assert "scim_tokens" not in set(inspect(create_engine_for(tmp_path)).get_table_names())
    migrate.upgrade(tmp_path)
    columns = {c["name"] for c in inspect(create_engine_for(tmp_path)).get_columns("users")}
    assert {"scim_external_id", "scim_deleted_at"} <= columns
