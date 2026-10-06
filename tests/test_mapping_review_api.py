"""Mapping review API: queue/history reads, decisions, scopes, and the agent guard."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

from security_lakehouse import api_legacy, api_v1
from security_lakehouse.auth.rbac import ROLE_SCOPES
from security_lakehouse.db.models import USER_ROLES
from security_lakehouse.mapping_review import list_decisions
from security_lakehouse.safeguards import load_safeguards


def _proposed_items(count: int, *, framework_id: str | None = None) -> list[dict[str, str]]:
    out = []
    for entry in load_safeguards()["safeguards"]:
        for member in entry["satisfies"]:
            if member.get("review_status") != "proposed":
                continue
            if framework_id and member["framework_id"] != framework_id:
                continue
            out.append(
                {
                    "safeguard_id": entry["safeguard_id"],
                    "control_id": member["control_id"],
                    "framework_id": member["framework_id"],
                }
            )
            if len(out) == count:
                return out
    raise AssertionError("not enough proposed mappings")


def _reviewed_item() -> dict[str, str]:
    for entry in load_safeguards()["safeguards"]:
        for member in entry["satisfies"]:
            if member.get("review_status", "reviewed") == "reviewed":
                return {
                    "safeguard_id": entry["safeguard_id"],
                    "control_id": member["control_id"],
                    "framework_id": member["framework_id"],
                }
    raise AssertionError("no reviewed mapping")


def _get(path: str, lake: Path, **params: str):
    return api_v1.handle_get(path, {key: [value] for key, value in params.items()}, lake)


# --- scopes --------------------------------------------------------------------


def test_mapping_review_scope_is_granted_to_admin_and_compliance_reviewer_only() -> None:
    assert "compliance_reviewer" in USER_ROLES
    holders = {role for role, scopes in ROLE_SCOPES.items() if "mapping_review" in scopes}
    assert holders == {"admin", "compliance_reviewer"}
    assert ROLE_SCOPES["compliance_reviewer"] == frozenset({"read", "mapping_review", "workpaper_review"})
    workpaper_holders = {role for role, scopes in ROLE_SCOPES.items() if "workpaper_review" in scopes}
    assert workpaper_holders == {"admin", "compliance_reviewer"}


def test_every_role_list_offers_the_compliance_reviewer_role() -> None:
    from pathlib import Path as _Path

    from security_lakehouse.auth.idp_roles import ROLE_RANK
    from security_lakehouse.cli import _USER_ROLE_CHOICES
    from security_lakehouse.data_policy import ROLE_SENSITIVITY_CEILING

    assert set(_USER_ROLE_CHOICES) == set(USER_ROLES) == set(ROLE_SCOPES) == set(ROLE_RANK)
    assert set(USER_ROLES) <= set(ROLE_SENSITIVITY_CEILING)
    web = _Path(__file__).parents[1] / "app/web/src/components/auth"
    for panel in ("UsersPanel.tsx", "InvitesPanel.tsx"):
        assert '"compliance_reviewer"' in (web / panel).read_text(encoding="utf-8"), panel


def test_decision_route_requires_mapping_review_scope_in_v1_and_legacy_tables() -> None:
    assert api_v1.required_post_scope("/api/v1/mapping-reviews/decisions") == "mapping_review"
    assert api_legacy.required_post_scope("/api/mapping-reviews/decisions") == "mapping_review"


def test_resource_catalog_documents_the_review_surface() -> None:
    catalog = {row["path"]: row for row in api_v1.resource_catalog()}
    assert catalog["/api/v1/mapping-reviews/queue"]["scopes"] == ["read"]
    assert catalog["/api/v1/mapping-reviews/summary"]["scopes"] == ["read"]
    decisions = catalog["/api/v1/mapping-reviews/decisions"]
    assert decisions["methods"] == ["GET", "POST"]
    assert decisions["scopes"] == ["read", "mapping_review"]


# --- local mode (transport-agnostic handlers) -------------------------------------


def test_queue_defaults_to_pending_and_is_paginated(tmp_path: Path) -> None:
    status, body = _get("/api/v1/mapping-reviews/queue", tmp_path, limit="25")
    assert status == HTTPStatus.OK
    assert body["meta"]["resource"] == "mapping-reviews.queue"
    assert body["meta"]["returned"] == 25
    assert body["meta"]["next_cursor"]
    assert {row["review_state"] for row in body["data"]} <= {"proposed", "needs_changes"}
    pending = sum(
        1
        for entry in load_safeguards()["safeguards"]
        for m in entry["satisfies"]
        if m.get("review_status") == "proposed" or m.get("control_version") != m.get("current_control_version")
    )
    assert body["meta"]["count"] == pending
    row = body["data"][0]
    for field in ("mapping_basis", "mapping_source", "reviewed_anchors", "control_title", "latest_decision"):
        assert field in row


def test_queue_filters_by_framework_family_safeguard_status_and_search(tmp_path: Path) -> None:
    item = _proposed_items(1, framework_id="fedramp-moderate")[0]
    _status, body = _get("/api/v1/mapping-reviews/queue", tmp_path, framework_id="fedramp-moderate", limit="1000")
    assert body["data"] and {row["framework_id"] for row in body["data"]} == {"fedramp-moderate"}
    _status, body = _get("/api/v1/mapping-reviews/queue", tmp_path, safeguard_id=item["safeguard_id"], limit="1000")
    assert {row["safeguard_id"] for row in body["data"]} == {item["safeguard_id"]}
    family = body["data"][0]["risk_domain"]
    _status, body = _get("/api/v1/mapping-reviews/queue", tmp_path, family=family, limit="1000")
    assert body["data"] and {row["risk_domain"] for row in body["data"]} == {family}
    _status, body = _get("/api/v1/mapping-reviews/queue", tmp_path, status="maintainer_reviewed", limit="1000")
    assert body["data"] and {row["review_state"] for row in body["data"]} == {"maintainer_reviewed"}
    _status, body = _get("/api/v1/mapping-reviews/queue", tmp_path, status="all", limit="1000")
    assert {row["review_state"] for row in body["data"]} >= {"maintainer_reviewed", "proposed"}
    _status, body = _get("/api/v1/mapping-reviews/queue", tmp_path, q=item["control_id"].lower(), status="all")
    assert any(row["control_id"] == item["control_id"] for row in body["data"])
    assert all(
        item["control_id"].lower()
        in " ".join(
            str(row.get(f) or "") for f in ("control_id", "safeguard_id", "safeguard_title", "control_title")
        ).lower()
        for row in body["data"]
    )


def test_local_post_records_decision_and_updates_queue_summary_coverage_and_oscal(tmp_path: Path) -> None:
    items = _proposed_items(2)
    status, body = api_v1.handle_post(
        "/api/v1/mapping-reviews/decisions",
        {"decision": "approve", "rationale": "Confirmed.", "reviewer": "grc@acme.test", "items": items},
        tmp_path,
    )
    assert status == HTTPStatus.CREATED, body
    assert body["meta"]["recorded"] == 2
    records = body["data"]
    assert {r["reviewer"] for r in records} == {"grc@acme.test"}
    assert {r["auth_method"] for r in records} == {"local-unauthenticated"}

    _status, queue = _get("/api/v1/mapping-reviews/queue", tmp_path, status="org_reviewed")
    assert {(r["safeguard_id"], r["control_id"]) for r in queue["data"]} == {
        (i["safeguard_id"], i["control_id"]) for i in items
    }
    assert queue["data"][0]["latest_decision"]["reviewer"] == "grc@acme.test"

    _status, summary = _get("/api/v1/mapping-reviews/summary", tmp_path)
    assert summary["data"]["totals"]["org_reviewed"] == 2
    assert summary["data"]["decision_log"]["ok"] is True
    families = summary["data"]["families"]
    assert families and all(set(row) == {"family_id", "label", "category_id", "category_label"} for row in families)
    assert all(row["category_id"] and row["category_label"] for row in families)
    assert {row["family_id"] for row in families} == {
        str(entry["risk_domain"]) for entry in load_safeguards()["safeguards"]
    }

    _status, coverage = _get("/api/v1/ccf/coverage", tmp_path)
    assert coverage["data"]["frameworks"]["org_reviewed_mappings"] == 2

    _status, oscal = _get("/api/v1/oscal/component-definition", tmp_path)
    props = [
        {p["name"]: p["value"] for p in req["props"]}
        for c in oscal["data"]["component-definition"]["components"]
        for impl in c.get("control-implementations", [])
        for req in impl["implemented-requirements"]
    ]
    org = [p for p in props if p.get("trustops-review-state") == "org-reviewed"]
    assert len(org) == 2 and {p["trustops-reviewed-by"] for p in org} == {"grc@acme.test"}


def test_local_post_requires_reviewer_and_rationale(tmp_path: Path) -> None:
    item = _proposed_items(1)
    status, body = api_v1.handle_post(
        "/api/v1/mapping-reviews/decisions", {"decision": "approve", "rationale": "ok", "items": item}, tmp_path
    )
    assert status == HTTPStatus.BAD_REQUEST
    assert "reviewer" in body["errors"][0]["detail"]
    status, body = api_v1.handle_post(
        "/api/v1/mapping-reviews/decisions",
        {"decision": "approve", "rationale": " ", "reviewer": "grc@acme.test", "items": item},
        tmp_path,
    )
    assert status == HTTPStatus.BAD_REQUEST
    assert "rationale" in body["errors"][0]["detail"]
    status, body = api_v1.handle_post(
        "/api/v1/mapping-reviews/decisions",
        {"decision": "approve", "rationale": "ok", "reviewer": "grc@acme.test", "items": "SG-1"},
        tmp_path,
    )
    assert status == HTTPStatus.BAD_REQUEST
    assert list_decisions(tmp_path) == []


def test_history_lists_superseded_decisions_for_one_mapping(tmp_path: Path) -> None:
    item = _reviewed_item()
    for decision in ("needs_changes", "reject"):
        api_v1.handle_post(
            "/api/v1/mapping-reviews/decisions",
            {"decision": decision, "rationale": f"{decision} note", "reviewer": "grc@acme.test", "items": [item]},
            tmp_path,
        )
    _status, body = _get(
        "/api/v1/mapping-reviews/decisions",
        tmp_path,
        safeguard_id=item["safeguard_id"],
        control_id=item["control_id"],
    )
    assert [row["decision"] for row in body["data"]] == ["needs_changes", "reject"]
    assert body["data"][1]["supersedes"] == body["data"][0]["decision_id"]
    _status, queue = _get("/api/v1/mapping-reviews/queue", tmp_path, status="rejected")
    assert [(r["safeguard_id"], r["control_id"]) for r in queue["data"]] == [(item["safeguard_id"], item["control_id"])]


# --- server mode -----------------------------------------------------------------

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient  # noqa: E402

from security_lakehouse.auth.sessions import SESSION_COOKIE  # noqa: E402
from security_lakehouse.db.base import session_scope  # noqa: E402
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user  # noqa: E402
from security_lakehouse.server_app import create_app  # noqa: E402
from test_api_v1 import _seed_lake  # noqa: E402

_ROLES = ("admin", "compliance_reviewer", "security_admin", "contributor", "auditor", "read_only")


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def server(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("TRUSTOPS_COOKIE_SIGNING_KEY", "mapping-review-test-signing-key")
    _seed_lake(tmp_path)  # a flat single-tenant lake, so decisions land at the root
    app = create_app(tmp_path)
    tokens: dict[str, str] = {}
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme Inc")
        for role in _ROLES:
            user = create_user(session, tenant_id=tenant.id, email=f"{role}@acme.test", role=role)
            _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id, name=f"{role}-key")
            tokens[role] = token
    return app, tokens, tmp_path


def _session_client(app, token: str) -> TestClient:
    from security_lakehouse.auth.sessions import encode_session_cookie
    from security_lakehouse.db.repository import create_user_session, resolve_api_key

    with session_scope(app.state.sessionmaker) as session:
        key = resolve_api_key(session, token)
        _, session_token = create_user_session(session, tenant_id=key.tenant_id, user_id=key.user_id, idp="oidc")
    client = TestClient(app)
    client.cookies.set(SESSION_COOKIE, encode_session_cookie(session_token))
    return client


def _decision_body(**overrides):
    return {
        "decision": "approve",
        "rationale": "Evidence verifies the clause.",
        "items": _proposed_items(1),
        **overrides,
    }


def test_session_reviewer_identity_comes_from_the_authenticated_user(server) -> None:
    app, tokens, lake = server
    client = _session_client(app, tokens["compliance_reviewer"])
    spoofed = client.post("/api/v1/mapping-reviews/decisions", json=_decision_body(reviewer="mallory@evil.test"))
    assert spoofed.status_code == HTTPStatus.UNPROCESSABLE_ENTITY
    assert "reviewer" in spoofed.json()["errors"][0]["detail"]
    assert list_decisions(lake) == []
    resp = client.post("/api/v1/mapping-reviews/decisions", json=_decision_body())
    assert resp.status_code == HTTPStatus.CREATED, resp.text
    record = resp.json()["data"][0]
    assert record["reviewer"] == "compliance_reviewer@acme.test"
    assert record["reviewer_role"] == "compliance_reviewer"
    assert record["reviewer_id"]
    assert record["auth_method"] == "session:oidc"
    assert list_decisions(lake)[0]["reviewer"] == "compliance_reviewer@acme.test"


def test_admin_session_can_decide(server) -> None:
    app, tokens, _lake = server
    client = _session_client(app, tokens["admin"])
    resp = client.post("/api/v1/mapping-reviews/decisions", json=_decision_body(decision="reject"))
    assert resp.status_code == HTTPStatus.CREATED


@pytest.mark.parametrize("role", ["security_admin", "contributor", "auditor", "read_only"])
def test_roles_without_mapping_review_scope_are_forbidden(server, role: str) -> None:
    app, tokens, lake = server
    client = _session_client(app, tokens[role])
    resp = client.post("/api/v1/mapping-reviews/decisions", json=_decision_body())
    assert resp.status_code == HTTPStatus.FORBIDDEN
    assert "mapping_review" in resp.json()["errors"][0]["detail"]
    assert list_decisions(lake) == []


@pytest.mark.parametrize("decision", ["approve", "reject", "needs_changes"])
def test_agent_api_key_can_list_but_never_decide(server, decision: str) -> None:
    app, tokens, lake = server
    client = TestClient(app)
    listed = client.get("/api/v1/mapping-reviews/queue?limit=5", headers=_bearer(tokens["admin"]))
    assert listed.status_code == HTTPStatus.OK
    assert listed.json()["meta"]["returned"] == 5
    history = client.get("/api/v1/mapping-reviews/decisions", headers=_bearer(tokens["compliance_reviewer"]))
    assert history.status_code == HTTPStatus.OK
    for role in ("admin", "compliance_reviewer"):
        resp = client.post(
            "/api/v1/mapping-reviews/decisions",
            json=_decision_body(decision=decision),
            headers=_bearer(tokens[role]),
        )
        assert resp.status_code == HTTPStatus.FORBIDDEN
        assert "signed-in" in resp.json()["errors"][0]["detail"]
    assert list_decisions(lake) == []


def test_legacy_route_cannot_bypass_the_guard(server) -> None:
    app, tokens, lake = server
    client = TestClient(app)
    resp = client.post(
        "/api/mapping-reviews/decisions",
        json={**_decision_body(), "reviewer": "agent"},
        headers=_bearer(tokens["admin"]),
    )
    assert resp.status_code >= HTTPStatus.BAD_REQUEST
    session_client = _session_client(app, tokens["admin"])
    resp = session_client.post("/api/mapping-reviews/decisions", json={**_decision_body(), "reviewer": "x"})
    assert resp.status_code >= HTTPStatus.BAD_REQUEST
    assert list_decisions(lake) == []


def test_invalid_decision_is_a_400_and_writes_nothing(server) -> None:
    app, tokens, lake = server
    client = _session_client(app, tokens["admin"])
    resp = client.post("/api/v1/mapping-reviews/decisions", json=_decision_body(rationale="  "))
    assert resp.status_code == HTTPStatus.BAD_REQUEST
    resp = client.post(
        "/api/v1/mapping-reviews/decisions",
        json=_decision_body(items=[{"safeguard_id": "SG-NOPE", "control_id": "X", "framework_id": "soc2"}]),
    )
    assert resp.status_code == HTTPStatus.BAD_REQUEST
    assert list_decisions(lake) == []


def test_tenants_see_only_their_own_decisions(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TRUSTOPS_COOKIE_SIGNING_KEY", "mapping-review-test-signing-key")
    _seed_lake(tmp_path)  # two tenants: the flat root is bound to nobody
    app = create_app(tmp_path)
    tokens = {}
    with session_scope(app.state.sessionmaker) as session:
        for slug in ("acme", "globex"):
            tenant = create_tenant(session, slug=slug, name=slug)
            user = create_user(session, tenant_id=tenant.id, email=f"grc@{slug}.test", role="compliance_reviewer")
            _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id, name="k")
            tokens[slug] = token
    item = _proposed_items(1)
    acme = _session_client(app, tokens["acme"])
    assert (
        acme.post("/api/v1/mapping-reviews/decisions", json=_decision_body(items=item)).status_code
        == HTTPStatus.CREATED
    )
    globex = _session_client(app, tokens["globex"])
    acme_history = acme.get("/api/v1/mapping-reviews/decisions").json()["data"]
    globex_history = globex.get("/api/v1/mapping-reviews/decisions").json()["data"]
    assert len(acme_history) == 1 and globex_history == []
    globex_state = globex.get(
        "/api/v1/mapping-reviews/queue",
        params={"safeguard_id": item[0]["safeguard_id"], "status": "all", "limit": "1000"},
    ).json()["data"]
    row = next(r for r in globex_state if r["control_id"] == item[0]["control_id"])
    assert row["review_state"] == "proposed"
    assert not (tmp_path / "gold" / "mapping_reviews.jsonl").exists()


def test_framework_coverage_route_reports_org_review_separately(server) -> None:
    app, tokens, _lake = server
    client = _session_client(app, tokens["compliance_reviewer"])
    before = client.get("/api/v1/frameworks/coverage").json()["data"]["summary"]
    assert before["org_reviewed_requirement_count"] == 0
    items = _proposed_items(40, framework_id="fedramp-moderate")
    assert client.post("/api/v1/mapping-reviews/decisions", json=_decision_body(items=items)).status_code == 201
    after = client.get("/api/v1/frameworks/coverage").json()["data"]
    summary = after["summary"]
    assert summary["org_reviewed_mapping_count"] == 40
    assert summary["maintainer_reviewed_requirement_count"] == before["maintainer_reviewed_requirement_count"]
    assert (
        summary["attestable_requirement_count"]
        == summary["maintainer_reviewed_requirement_count"] + summary["org_reviewed_requirement_count"]
    )
    fedramp = next(row for row in after["frameworks"] if row["framework_id"] == "fedramp-moderate")
    assert fedramp["org_reviewed_mapping_count"] == 40


# --- integrity + server-mode guard ----------------------------------------------


def test_coverage_payloads_report_review_log_verified(tmp_path: Path, monkeypatch) -> None:
    from security_lakehouse.framework_coverage import build_framework_coverage, framework_coverage_summary
    from security_lakehouse.mapping_review import review_log_path

    monkeypatch.delenv("TRUSTOPS_COOKIE_SIGNING_KEY", raising=False)
    items = _proposed_items(1)
    api_v1.handle_post(
        "/api/v1/mapping-reviews/decisions",
        {"decision": "approve", "rationale": "Confirmed.", "reviewer": "grc@acme.test", "items": items},
        tmp_path,
    )
    _status, coverage = _get("/api/v1/ccf/coverage", tmp_path)
    assert coverage["data"]["review_log_verified"] is True
    assert coverage["data"]["frameworks"]["org_reviewed_mappings"] == 1

    path = review_log_path(tmp_path)
    path.write_text(path.read_text(encoding="utf-8").replace("Confirmed.", "Forged."), encoding="utf-8")

    _status, coverage = _get("/api/v1/ccf/coverage", tmp_path)
    assert coverage["data"]["review_log_verified"] is False
    assert coverage["data"]["frameworks"]["org_reviewed_mappings"] == 0
    _status, summary = _get("/api/v1/mapping-reviews/summary", tmp_path)
    assert summary["data"]["review_log_verified"] is False
    assert summary["data"]["totals"]["org_reviewed"] == 0
    rows = build_framework_coverage(lake_dir=tmp_path)
    assert rows and all(row["review_log_verified"] is False for row in rows)
    assert framework_coverage_summary(rows)["review_log_verified"] is False


def test_handle_post_refuses_unauthenticated_decisions_in_server_mode(tmp_path: Path) -> None:
    from security_lakehouse.execution_mode import server_execution

    items = _proposed_items(1)
    with server_execution("t1"):
        status, body = api_v1.handle_post(
            "/api/v1/mapping-reviews/decisions",
            {"decision": "approve", "rationale": "Confirmed.", "reviewer": "forged@acme.test", "items": items},
            tmp_path,
        )
    assert status == HTTPStatus.FORBIDDEN, body
    assert body["errors"][0]["code"] == "forbidden"
    assert list_decisions(tmp_path) == []
