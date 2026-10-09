"""Tags + saved views tests: data-model lifecycle, uniqueness, and API RBAC matrix."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from security_lakehouse.db import tags as tags_db
from security_lakehouse.db.base import session_scope
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
    tokens: dict[str, str] = {}
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        for role in ("read_only", "contributor", "security_admin"):
            user = create_user(session, tenant_id=tenant.id, email=f"{role}@acme.test", role=role)
            _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
            tokens[role] = token
    return app, client, tokens


# ---------------------------------------------------------------------------
# Data-model layer
# ---------------------------------------------------------------------------


def test_create_and_list_tags(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        t1 = tags_db.create_tag(session, tenant_id=tenant.id, name="soc2", color="#4f46e5")
        t2 = tags_db.create_tag(session, tenant_id=tenant.id, name="critical", color="#ef4444")
        all_tags = tags_db.list_tags(session, tenant_id=tenant.id)
        assert len(all_tags) == 2
        ids = {t.id for t in all_tags}
        assert t1.id in ids
        assert t2.id in ids


def test_tag_name_unique_per_tenant(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        tags_db.create_tag(session, tenant_id=tenant.id, name="soc2")
        with pytest.raises(ValueError, match="already exists"):
            tags_db.create_tag(session, tenant_id=tenant.id, name="soc2")


def test_tag_name_blank_rejected(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        with pytest.raises(ValueError, match="blank"):
            tags_db.create_tag(session, tenant_id=tenant.id, name="  ")


def test_delete_tag(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        tag = tags_db.create_tag(session, tenant_id=tenant.id, name="temp")
        assert tags_db.delete_tag(session, tenant_id=tenant.id, tag_id=tag.id) is True
        assert tags_db.delete_tag(session, tenant_id=tenant.id, tag_id=tag.id) is False


def test_attach_detach_and_tags_for_entity(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        t1 = tags_db.create_tag(session, tenant_id=tenant.id, name="soc2")
        t2 = tags_db.create_tag(session, tenant_id=tenant.id, name="pci")

        tags_db.attach_tag(session, tenant_id=tenant.id, tag_id=t1.id, entity_type="violation", entity_id="v-001")
        tags_db.attach_tag(session, tenant_id=tenant.id, tag_id=t2.id, entity_type="violation", entity_id="v-001")

        entity_tags = tags_db.tags_for_entity(session, tenant_id=tenant.id, entity_type="violation", entity_id="v-001")
        assert len(entity_tags) == 2

        # Idempotent attach
        tags_db.attach_tag(session, tenant_id=tenant.id, tag_id=t1.id, entity_type="violation", entity_id="v-001")
        entity_tags = tags_db.tags_for_entity(session, tenant_id=tenant.id, entity_type="violation", entity_id="v-001")
        assert len(entity_tags) == 2

        # Detach
        assert (
            tags_db.detach_tag(session, tenant_id=tenant.id, tag_id=t1.id, entity_type="violation", entity_id="v-001")
            is True
        )
        entity_tags = tags_db.tags_for_entity(session, tenant_id=tenant.id, entity_type="violation", entity_id="v-001")
        assert len(entity_tags) == 1
        assert entity_tags[0].id == t2.id


def test_entity_ids_for_tag_filters_by_type(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        tag = tags_db.create_tag(session, tenant_id=tenant.id, name="audit-q3")
        tags_db.attach_tag(session, tenant_id=tenant.id, tag_id=tag.id, entity_type="violation", entity_id="v-001")
        tags_db.attach_tag(session, tenant_id=tenant.id, tag_id=tag.id, entity_type="control", entity_id="SOC2-CC6.1")
        tags_db.attach_tag(session, tenant_id=tenant.id, tag_id=tag.id, entity_type="evidence", entity_id="evt-9")

        all_ids = tags_db.entity_ids_for_tag(session, tenant_id=tenant.id, tag_id=tag.id)
        assert all_ids == ["SOC2-CC6.1", "evt-9", "v-001"]

        violations = tags_db.entity_ids_for_tag(session, tenant_id=tenant.id, tag_id=tag.id, entity_type="violation")
        assert violations == ["v-001"]

        assert tags_db.entity_ids_for_tag(session, tenant_id=tenant.id, tag_id="missing") == []


def test_attach_unknown_tag_raises(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        with pytest.raises(ValueError, match="not found"):
            tags_db.attach_tag(
                session, tenant_id=tenant.id, tag_id="nonexistent", entity_type="violation", entity_id="v-001"
            )


def test_saved_view_lifecycle(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        v = tags_db.create_saved_view(
            session,
            tenant_id=tenant.id,
            surface="violations",
            name="Critical only",
            filters={"severity": "critical"},
            created_by="alice@acme.test",
        )
        assert v.surface == "violations"

        rows = tags_db.list_saved_views(session, tenant_id=tenant.id)
        assert len(rows) == 1

        rows_filtered = tags_db.list_saved_views(session, tenant_id=tenant.id, surface="violations")
        assert len(rows_filtered) == 1

        rows_other = tags_db.list_saved_views(session, tenant_id=tenant.id, surface="controls")
        assert len(rows_other) == 0

        d = tags_db.saved_view_to_dict(v)
        assert d["filters"] == {"severity": "critical"}

        assert tags_db.delete_saved_view(session, tenant_id=tenant.id, view_id=v.id) is True
        assert tags_db.delete_saved_view(session, tenant_id=tenant.id, view_id=v.id) is False


def test_saved_view_blank_name_rejected(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        with pytest.raises(ValueError, match="name"):
            tags_db.create_saved_view(session, tenant_id=tenant.id, surface="violations", name="", filters={})


# ---------------------------------------------------------------------------
# API layer
# ---------------------------------------------------------------------------


def test_tags_require_auth(env) -> None:
    _app, client, _tokens = env
    assert client.get("/api/v1/tags").status_code == HTTPStatus.UNAUTHORIZED
    assert client.post("/api/v1/tags", json={"name": "x"}).status_code == HTTPStatus.UNAUTHORIZED


def test_tag_crud_and_rbac(env) -> None:
    _app, client, tokens = env

    # read_only can list
    resp = client.get("/api/v1/tags", headers=_bearer(tokens["read_only"]))
    assert resp.status_code == HTTPStatus.OK
    assert resp.json()["data"] == []

    # read_only cannot create
    denied = client.post("/api/v1/tags", json={"name": "soc2"}, headers=_bearer(tokens["read_only"]))
    assert denied.status_code == HTTPStatus.FORBIDDEN

    # contributor can create
    created = client.post(
        "/api/v1/tags", json={"name": "soc2", "color": "#4f46e5"}, headers=_bearer(tokens["contributor"])
    )
    assert created.status_code == HTTPStatus.CREATED
    tag = created.json()["data"]
    assert tag["name"] == "soc2"
    assert tag["color"] == "#4f46e5"

    # duplicate name → 400
    dup = client.post("/api/v1/tags", json={"name": "soc2"}, headers=_bearer(tokens["contributor"]))
    assert dup.status_code == HTTPStatus.BAD_REQUEST

    # list now has 1
    listed = client.get("/api/v1/tags", headers=_bearer(tokens["contributor"]))
    assert len(listed.json()["data"]) == 1

    # delete
    deleted = client.delete(f"/api/v1/tags/{tag['id']}", headers=_bearer(tokens["contributor"]))
    assert deleted.status_code == HTTPStatus.OK

    # 404 for missing tag
    resp404 = client.delete(f"/api/v1/tags/{tag['id']}", headers=_bearer(tokens["contributor"]))
    assert resp404.status_code == HTTPStatus.NOT_FOUND


def test_attach_detach_rbac(env) -> None:
    _app, client, tokens = env

    created = client.post("/api/v1/tags", json={"name": "pci"}, headers=_bearer(tokens["contributor"]))
    tag_id = created.json()["data"]["id"]

    # attach
    attach_body = {"tag_id": tag_id, "entity_type": "violation", "entity_id": "v-001"}
    resp = client.post("/api/v1/tags/attach", json=attach_body, headers=_bearer(tokens["contributor"]))
    assert resp.status_code == HTTPStatus.CREATED

    # for endpoint
    for_resp = client.get(
        "/api/v1/tags/for?entity_type=violation&entity_id=v-001", headers=_bearer(tokens["read_only"])
    )
    assert for_resp.status_code == HTTPStatus.OK
    assert len(for_resp.json()["data"]) == 1

    # detach
    detach_resp = client.post("/api/v1/tags/detach", json=attach_body, headers=_bearer(tokens["contributor"]))
    assert detach_resp.status_code == HTTPStatus.OK

    # 404 on re-detach
    resp404 = client.post("/api/v1/tags/detach", json=attach_body, headers=_bearer(tokens["contributor"]))
    assert resp404.status_code == HTTPStatus.NOT_FOUND


def test_tags_for_missing_params(env) -> None:
    _app, client, tokens = env
    resp = client.get("/api/v1/tags/for", headers=_bearer(tokens["read_only"]))
    assert resp.status_code == HTTPStatus.BAD_REQUEST


def test_tag_entities_api(env) -> None:
    _app, client, tokens = env

    created = client.post("/api/v1/tags", json={"name": "q3-audit"}, headers=_bearer(tokens["contributor"]))
    tag_id = created.json()["data"]["id"]
    attach = {"tag_id": tag_id, "entity_type": "violation", "entity_id": "v-99"}
    client.post("/api/v1/tags/attach", json=attach, headers=_bearer(tokens["contributor"]))

    resp = client.get(
        f"/api/v1/tags/entities?tag_id={tag_id}&entity_type=violation",
        headers=_bearer(tokens["read_only"]),
    )
    assert resp.status_code == HTTPStatus.OK
    assert resp.json()["data"] == ["v-99"]
    assert resp.json()["meta"]["resource"] == "tags.entities"


def test_saved_views_crud_and_rbac(env) -> None:
    _app, client, tokens = env

    # read_only can list
    resp = client.get("/api/v1/saved-views", headers=_bearer(tokens["read_only"]))
    assert resp.status_code == HTTPStatus.OK

    # read_only cannot create
    denied = client.post(
        "/api/v1/saved-views",
        json={"surface": "violations", "name": "My view", "filters": {}},
        headers=_bearer(tokens["read_only"]),
    )
    assert denied.status_code == HTTPStatus.FORBIDDEN

    # contributor can create
    created = client.post(
        "/api/v1/saved-views",
        json={"surface": "violations", "name": "Critical only", "filters": {"severity": "critical"}},
        headers=_bearer(tokens["contributor"]),
    )
    assert created.status_code == HTTPStatus.CREATED
    view = created.json()["data"]
    assert view["name"] == "Critical only"
    assert view["filters"] == {"severity": "critical"}

    # filter by surface
    resp_filtered = client.get("/api/v1/saved-views?surface=violations", headers=_bearer(tokens["read_only"]))
    assert len(resp_filtered.json()["data"]) == 1

    resp_other = client.get("/api/v1/saved-views?surface=controls", headers=_bearer(tokens["read_only"]))
    assert len(resp_other.json()["data"]) == 0

    # delete
    del_resp = client.delete(f"/api/v1/saved-views/{view['id']}", headers=_bearer(tokens["contributor"]))
    assert del_resp.status_code == HTTPStatus.OK

    # 404 on re-delete
    resp404 = client.delete(f"/api/v1/saved-views/{view['id']}", headers=_bearer(tokens["contributor"]))
    assert resp404.status_code == HTTPStatus.NOT_FOUND
