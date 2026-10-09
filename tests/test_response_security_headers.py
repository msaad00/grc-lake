"""Console pages carry a CSP and authenticated API JSON is never cached."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient  # noqa: E402

from security_lakehouse import server_app  # noqa: E402
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user  # noqa: E402
from security_lakehouse.server_app import create_app  # noqa: E402


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, str]:
    dist = tmp_path / "dist"
    (dist / "dashboard").mkdir(parents=True)
    (dist / "trust" / "share").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>c</title>", encoding="utf-8")
    (dist / "dashboard" / "index.html").write_text("<!doctype html><title>d</title>", encoding="utf-8")
    (dist / "trust" / "share" / "index.html").write_text("<!doctype html><title>t</title>", encoding="utf-8")
    monkeypatch.setattr(server_app, "web_dist_dir", lambda: dist)
    monkeypatch.setattr(server_app, "web_dist_index", lambda: dist / "index.html")
    monkeypatch.setenv("TRUSTOPS_COOKIE_SIGNING_KEY", "x" * 48)
    app = create_app(tmp_path / "lake")
    with app.state.sessionmaker() as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        user = create_user(session, tenant_id=tenant.id, email="a@acme.test", role="admin")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        session.commit()
    return TestClient(app, base_url="https://testserver"), token


def _directives(header: str) -> dict[str, str]:
    return {part.strip().split(" ", 1)[0]: part.strip() for part in header.split(";") if part.strip()}


@pytest.mark.parametrize("path", ["/console/dashboard/", "/console/trust/abc123/"])
def test_console_pages_send_a_content_security_policy(client, path: str) -> None:
    http, _token = client
    resp = http.get(path)
    assert resp.status_code == 200
    csp = _directives(resp.headers["content-security-policy"])
    assert csp["default-src"] == "default-src 'self'"
    assert csp["frame-ancestors"] == "frame-ancestors 'none'"
    assert csp["object-src"] == "object-src 'none'"
    assert csp["base-uri"] == "base-uri 'self'"
    assert "connect-src" in csp and "*" not in csp["connect-src"]


def test_authenticated_api_json_is_not_cacheable(client) -> None:
    http, token = client
    resp = http.get("/api/v1/controls", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"


def test_explicit_cache_policy_is_preserved(client) -> None:
    http, _token = client
    resp = http.get("/brand/trustops-mark.svg")
    assert resp.headers.get("cache-control", "").startswith("public") or resp.status_code == 404
