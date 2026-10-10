"""Server-mode auth guard, status-code, input-bound, and contract regressions."""

from __future__ import annotations

import logging
import re
from argparse import Namespace
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from security_lakehouse import api_v1, cli
from security_lakehouse.auth import server_mode
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
from security_lakehouse.runtime_environment import runtime_env
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake

_ENV_KEYS = ("ENV", "ALLOW_INSECURE_NO_AUTH")


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for key in _ENV_KEYS:
        monkeypatch.delenv("GRC_LAKE_" + key, raising=False)
        monkeypatch.delenv("TRUSTOPS_" + key, raising=False)
    return monkeypatch


# --- 1. production guard ------------------------------------------------------


def test_empty_new_prefix_does_not_mask_a_legacy_value() -> None:
    env = runtime_env({"TRUSTOPS_ENV": "production", "GRC_LAKE_ENV": ""})
    assert env["GRC_LAKE_ENV"] == "production"
    assert env["TRUSTOPS_ENV"] == "production"


def test_non_empty_new_prefix_still_wins_and_empty_pairs_stay_empty() -> None:
    assert runtime_env({"TRUSTOPS_ENV": "production", "GRC_LAKE_ENV": "dev"})["GRC_LAKE_ENV"] == "dev"
    assert runtime_env({"TRUSTOPS_ENV": "", "GRC_LAKE_ENV": ""})["GRC_LAKE_ENV"] == ""
    assert runtime_env({"GRC_LAKE_ENV": ""})["TRUSTOPS_ENV"] == ""


def test_empty_new_env_cannot_unlock_no_auth_under_legacy_production(tmp_path: Path, clean_env) -> None:
    clean_env.setenv("TRUSTOPS_ENV", "production")
    clean_env.setenv("GRC_LAKE_ENV", "")
    clean_env.setattr("uvicorn.run", lambda *args, **kwargs: None)
    with pytest.raises(RuntimeError, match="forbidden"):
        cli._serve(Namespace(server=True, allow_insecure_no_auth=True, lake=tmp_path, host="127.0.0.1", port=0))


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.9", "::1", "localhost"])
def test_unset_env_allows_no_auth_on_loopback(clean_env, host: str) -> None:
    server_mode.assert_insecure_allowed(require_auth=False, host=host)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "10.0.0.4", "grc.example.internal"])
def test_unset_env_refuses_no_auth_on_a_routable_bind(clean_env, host: str) -> None:
    with pytest.raises(RuntimeError) as excinfo:
        server_mode.assert_insecure_allowed(require_auth=False, host=host)
    message = str(excinfo.value)
    assert host in message
    assert "GRC_LAKE_ENV=demo" in message
    assert "127.0.0.1" in message


@pytest.mark.parametrize("environment", ["dev", "development", "local", "demo", "test", " Demo "])
def test_named_non_production_env_allows_no_auth_on_any_bind(clean_env, environment: str) -> None:
    clean_env.setenv("GRC_LAKE_ENV", environment)
    server_mode.assert_insecure_allowed(require_auth=False, host="0.0.0.0")


@pytest.mark.parametrize("environment", ["qa", "uat", "preprod"])
def test_unknown_env_fails_closed_even_on_loopback(clean_env, environment: str) -> None:
    clean_env.setenv("GRC_LAKE_ENV", environment)
    with pytest.raises(RuntimeError, match="GRC_LAKE_ENV"):
        server_mode.assert_insecure_allowed(require_auth=False, host="127.0.0.1")


def test_authenticated_mode_is_never_refused(clean_env) -> None:
    clean_env.setenv("GRC_LAKE_ENV", "production")
    server_mode.assert_insecure_allowed(require_auth=True, host="0.0.0.0")


@pytest.mark.parametrize("via", ["flag", "environment"])
def test_cli_server_refuses_routable_no_auth_without_env(tmp_path: Path, clean_env, via: str) -> None:
    clean_env.setattr("uvicorn.run", lambda *args, **kwargs: None)
    if via == "environment":
        clean_env.setenv("GRC_LAKE_ALLOW_INSECURE_NO_AUTH", "true")
    args = Namespace(server=True, allow_insecure_no_auth=via == "flag", lake=tmp_path, host="0.0.0.0", port=0)
    with pytest.raises(RuntimeError, match="loopback"):
        cli._serve(args)
    assert not (tmp_path / "gold").exists()


def test_cli_server_starts_the_demo_on_all_interfaces(tmp_path: Path, clean_env) -> None:
    calls: list[dict] = []
    clean_env.setenv("GRC_LAKE_ENV", "demo")
    clean_env.setattr("uvicorn.run", lambda app, **kwargs: calls.append(kwargs))
    cli._serve(Namespace(server=True, allow_insecure_no_auth=True, lake=tmp_path, host="0.0.0.0", port=0))
    assert calls == [{"host": "0.0.0.0", "port": 0}]


def test_compose_demo_declares_a_demo_environment() -> None:
    import yaml

    compose = yaml.safe_load((Path(__file__).resolve().parents[1] / "compose.yaml").read_text(encoding="utf-8"))
    demo = compose["services"]["grc-lake"]
    assert demo["environment"]["GRC_LAKE_ENV"] == "demo"


# --- helpers ------------------------------------------------------------------


def _tenant_client(tmp_path: Path, *, role: str = "admin", slug: str = "acme"):
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug=slug, name=slug.title())
        user = create_user(session, tenant_id=tenant.id, email=f"{role}@{slug}.test", role=role)
        _, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
    return app, TestClient(app), {"Authorization": f"Bearer {token}"}


def _add_tenant_admin(app, slug: str):
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug=slug, name=slug.title())
        user = create_user(session, tenant_id=tenant.id, email=f"admin@{slug}.test", role="admin")
        _, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        return user.id, {"Authorization": f"Bearer {token}"}


# --- 2. legacy brand mark -----------------------------------------------------


@pytest.mark.parametrize("path", ["/brand/grc-lake-mark.svg", "/brand/trustops-mark.svg"])
def test_brand_mark_is_served_at_new_and_legacy_paths(tmp_path: Path, path: str) -> None:
    client = TestClient(create_app(tmp_path, require_auth=False))
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert response.content.lstrip().startswith(b"<svg")


# --- 3. verify + revoke status codes ------------------------------------------


def test_evidence_verify_is_a_read_and_returns_200(tmp_path: Path) -> None:
    _app, client, headers = _tenant_client(tmp_path, role="auditor")
    evidence = client.get("/api/v1/evidence?limit=1", headers=headers).json()["data"]
    assert evidence, "seeded lake has evidence"
    event_id = evidence[0]["event_id"]
    response = client.post(f"/api/v1/evidence/{event_id}/verify", headers=headers, json={})
    assert response.status_code == 200, response.text
    assert response.json()["data"]["event_id"] == event_id
    assert api_v1.required_post_scope(f"/api/v1/evidence/{event_id}/verify") == "read"


def test_evidence_verify_of_an_unknown_event_is_404(tmp_path: Path) -> None:
    _app, client, headers = _tenant_client(tmp_path)
    response = client.post("/api/v1/evidence/no-such-event/verify", headers=headers, json={})
    assert response.status_code == 404
    assert response.json()["errors"][0]["code"] == "not_found"


@pytest.mark.parametrize("prefix", ["/api/v1", "/api"])
def test_trust_share_revoke_returns_200(tmp_path: Path, prefix: str) -> None:
    _app, client, headers = _tenant_client(tmp_path)
    share = client.post("/api/v1/trust-shares", headers=headers, json={"role": "auditor"}).json()["data"]
    response = client.post(f"{prefix}/trust-shares/{share['share_id']}/revoke", headers=headers, json={})
    assert response.status_code == 200, response.text


# --- 4. cross-tenant user patch -----------------------------------------------


def test_cross_tenant_user_patch_is_not_found(tmp_path: Path) -> None:
    app, client, headers = _tenant_client(tmp_path)
    other_user_id, _ = _add_tenant_admin(app, "other")
    response = client.patch(f"/api/v1/auth/users/{other_user_id}", headers=headers, json={"display_name": "x"})
    assert response.status_code == 404
    assert response.json()["errors"][0]["code"] == "not_found"


def test_user_patch_rule_violation_is_still_400(tmp_path: Path) -> None:
    app, client, headers = _tenant_client(tmp_path)
    users = client.get("/api/v1/auth/users", headers=headers).json()["data"]
    response = client.patch(f"/api/v1/auth/users/{users[0]['id']}", headers=headers, json={"is_active": False})
    assert response.status_code == 400


# --- 5. unmapped-scope message ------------------------------------------------


@pytest.mark.parametrize("path", ["/api/no-such-operation", "/api/v1/no-such-operation"])
def test_unmapped_post_does_not_leak_internal_scope_name(tmp_path: Path, path: str) -> None:
    _app, client, headers = _tenant_client(tmp_path)
    response = client.post(path, headers=headers, json={})
    assert response.status_code == 403
    assert "__unmapped" not in response.text
    assert "not a supported operation" in response.json()["errors"][0]["detail"]


# --- 6. CSRF Sec-Fetch-Site backstop ------------------------------------------


def _cookie_client(tmp_path: Path) -> TestClient:
    from security_lakehouse.auth.sessions import SESSION_COOKIE, encode_session_cookie
    from security_lakehouse.db.repository import create_user_session

    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        user = create_user(session, tenant_id=tenant.id, email="admin@acme.test", role="admin")
        _row, session_token = create_user_session(session, tenant_id=tenant.id, user_id=user.id)
    client = TestClient(app, base_url="https://testserver")
    client.cookies.set(SESSION_COOKIE, encode_session_cookie(session_token))
    return client


def test_cookie_mutation_marked_cross_site_without_origin_is_refused(tmp_path: Path) -> None:
    client = _cookie_client(tmp_path)
    response = client.post(
        "/api/v1/snapshots",
        content=b'{"reason":"csrf"}',
        headers={"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"},
    )
    assert response.status_code == 403
    assert response.json()["errors"][0]["detail"] == "cross-origin request refused"
    assert client.get("/api/v1/snapshots").json()["data"] == []


@pytest.mark.parametrize("site", ["same-origin", "same-site", "none"])
def test_cookie_mutation_with_benign_sec_fetch_site_is_allowed(tmp_path: Path, site: str) -> None:
    client = _cookie_client(tmp_path)
    response = client.post(
        "/api/v1/snapshots",
        content=b'{"reason":"ok"}',
        headers={"Content-Type": "application/json", "Sec-Fetch-Site": site},
    )
    assert response.status_code == 201


# --- 7. request field bounds --------------------------------------------------


@pytest.mark.parametrize(
    "path,payload",
    [
        ("/api/v1/risks", {"title": "x" * 2_000_000}),
        ("/api/v1/risks", {"title": "ok", "description": "x" * 20_001}),
        ("/api/v1/remediation/tasks", {"title": "x" * 501}),
        ("/api/v1/tags", {"name": "x" * 201}),
    ],
)
def test_oversized_request_fields_are_rejected(tmp_path: Path, path: str, payload: dict) -> None:
    _app, client, headers = _tenant_client(tmp_path)
    response = client.post(path, headers=headers, json=payload)
    assert response.status_code == 422
    assert "at most" in response.json()["errors"][0]["detail"]


def test_request_fields_at_the_bound_are_accepted(tmp_path: Path) -> None:
    _app, client, headers = _tenant_client(tmp_path)
    response = client.post("/api/v1/risks", headers=headers, json={"title": "x" * 500, "description": "y" * 20_000})
    assert response.status_code == 201


def test_every_string_request_field_is_bounded() -> None:
    from typing import get_args

    from pydantic import BaseModel

    from security_lakehouse import server_app

    def unbounded(annotation, metadata) -> bool:
        if any(getattr(item, "max_length", None) for item in metadata):
            return False
        return annotation is str or str in get_args(annotation)

    models = [
        value
        for value in vars(server_app).values()
        if isinstance(value, type) and issubclass(value, BaseModel) and value.__module__ == server_app.__name__
    ]
    assert models
    offenders = [
        f"{model.__name__}.{name}"
        for model in models
        for name, field in model.model_fields.items()
        if unbounded(field.annotation, field.metadata)
    ]
    assert offenders == []


# --- 8. pagination contract ---------------------------------------------------


def _create_rows(client: TestClient, headers: dict, path: str, payloads: list[dict]) -> None:
    for payload in payloads:
        assert client.post(path, headers=headers, json=payload).status_code == 201, path


_PAGED = {
    "/api/v1/risks": [{"title": f"risk {n}"} for n in range(3)],
    "/api/v1/remediation/tasks": [{"title": f"task {n}"} for n in range(3)],
    "/api/v1/webhooks": [
        {"url": f"https://hooks.example.com/{n}", "event_types": ["assessment.completed"]} for n in range(3)
    ],
}


@pytest.mark.parametrize("path", sorted(_PAGED))
def test_db_backed_lists_report_total_and_cursor(tmp_path: Path, path: str) -> None:
    _app, client, headers = _tenant_client(tmp_path)
    _create_rows(client, headers, path, _PAGED[path])
    first = client.get(f"{path}?limit=2", headers=headers)
    assert first.status_code == 200, first.text
    meta = first.json()["meta"]
    assert (meta["count"], meta["returned"], meta["limit"], meta["offset"]) == (3, 2, 2, 0)
    assert meta["next_cursor"]
    second = client.get(f"{path}?limit=2&cursor={meta['next_cursor']}", headers=headers).json()
    assert (second["meta"]["count"], second["meta"]["returned"], second["meta"]["next_cursor"]) == (3, 1, None)
    ids = {row["id"] for row in first.json()["data"]} | {row["id"] for row in second["data"]}
    assert len(ids) == 3


@pytest.mark.parametrize(
    "path",
    ["/api/v1/risks", "/api/v1/remediation/tasks", "/api/v1/webhooks", "/api/v1/auth/users", "/api/v1/audit-log"],
)
@pytest.mark.parametrize("query", ["limit=abc", "limit=0", "limit=99999", "offset=-1", "offset=x", "cursor=bogus"])
def test_lists_reject_bad_paging_like_evidence(tmp_path: Path, path: str, query: str) -> None:
    _app, client, headers = _tenant_client(tmp_path)
    assert client.get(f"/api/v1/evidence?{query}", headers=headers).status_code == 400
    response = client.get(f"{path}?{query}", headers=headers)
    assert response.status_code == 400, (path, query, response.text)
    assert response.json()["errors"][0]["code"] == "bad_request"


def test_user_list_pages_with_total(tmp_path: Path) -> None:
    from sqlalchemy import select

    from security_lakehouse.db.models import Tenant

    app, client, headers = _tenant_client(tmp_path)
    _add_tenant_admin(app, "other")
    with session_scope(app.state.sessionmaker) as session:
        tenant_id = session.scalar(select(Tenant.id).where(Tenant.slug == "acme"))
        for n in range(2):
            create_user(session, tenant_id=tenant_id, email=f"member{n}@acme.test", role="read_only")
    body = client.get("/api/v1/auth/users?limit=1", headers=headers).json()
    assert (body["meta"]["count"], body["meta"]["returned"]) == (3, 1)
    assert body["meta"]["next_cursor"]


def test_audit_log_pages_with_total(tmp_path: Path) -> None:
    _app, client, headers = _tenant_client(tmp_path)
    for n in range(3):
        assert client.post("/api/v1/snapshots", headers=headers, json={"reason": f"r{n}"}).status_code == 201
    full = client.get("/api/v1/audit-log", headers=headers).json()
    total = full["meta"]["count"]
    assert total >= 3
    page = client.get("/api/v1/audit-log?limit=1", headers=headers).json()
    assert (page["meta"]["count"], page["meta"]["returned"]) == (total, 1)
    assert page["meta"]["next_cursor"]


# --- 9. OpenAPI validity ------------------------------------------------------


def _merged_spec(tmp_path: Path) -> dict:
    return api_v1.merge_openapi(create_app(tmp_path, require_auth=False).openapi())


def test_openapi_operation_ids_are_unique(tmp_path: Path) -> None:
    seen: dict[str, list[str]] = {}
    for path, item in _merged_spec(tmp_path)["paths"].items():
        for method, operation in item.items():
            if isinstance(operation, dict) and "operationId" in operation:
                seen.setdefault(operation["operationId"], []).append(f"{method.upper()} {path}")
    duplicates = {key: value for key, value in seen.items() if len(value) > 1}
    assert duplicates == {}


def test_openapi_declares_every_templated_path_parameter(tmp_path: Path) -> None:
    missing = []
    for path, item in _merged_spec(tmp_path)["paths"].items():
        templated = set(re.findall(r"{([^}]+)}", path))
        shared = {p["name"] for p in item.get("parameters", []) if p.get("in") == "path"}
        for method, operation in item.items():
            if method == "parameters" or not isinstance(operation, dict):
                continue
            declared = shared | {p["name"] for p in operation.get("parameters", []) if p.get("in") == "path"}
            missing.extend(f"{method.upper()} {path}: {name}" for name in sorted(templated - declared))
    assert missing == []


def test_openapi_command_does_not_warn_about_no_auth(tmp_path: Path, clean_env, caplog, capsys) -> None:
    caplog.set_level(logging.WARNING)
    assert cli.main(["openapi", "--out", str(tmp_path / "spec.json")]) == 0
    captured = capsys.readouterr()
    assert "Unauthenticated" not in caplog.text
    assert "Unauthenticated" not in captured.err + captured.out


def test_distributed_request_count_is_the_unbounded_total(tmp_path: Path) -> None:
    import json

    from security_lakehouse.db.models import DistributedRequestAudit
    from security_lakehouse.distributed.audit import request_count, request_rows

    factory = create_app(tmp_path, require_auth=False).state.sessionmaker
    with session_scope(factory) as session:
        for n in range(5):
            event = json.dumps({"actor": "a" if n < 3 else "b"})
            session.add(DistributedRequestAudit(event_id=f"e{n}", cluster_id="c", tenant_id="t", event_json=event))
        session.add(
            DistributedRequestAudit(event_id="x", cluster_id="c", tenant_id="other", event_json='{"actor":"a"}')
        )
    assert len(request_rows(factory, "c", "t", limit=2)) == 2
    assert request_count(factory, "c", "t") == 5
    # The actor predicate is shared with request_rows, so the two always agree.
    assert request_count(factory, "c", "t", actor="a") == len(request_rows(factory, "c", "t", actor="a", limit=100))
