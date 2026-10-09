"""Connector credentials never reach the audit log, and URLs cannot carry them."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient  # noqa: E402

from security_lakehouse.audit_log import build_audit_log  # noqa: E402
from security_lakehouse.connector_state import append_config_event, configure_payload_error  # noqa: E402
from security_lakehouse.db.repository import create_api_key, create_tenant, create_user  # noqa: E402
from security_lakehouse.server_app import create_app  # noqa: E402

SECRETS = {
    "apikey": "SEKRET_APIKEY_123456",
    "authorization": "Bearer SEKRET_AUTH_123456",
    "passphrase": "SEKRET_PASSPHRASE_123456",
    "token": "SEKRET_TOKEN_123456",
}


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_audit_log_masks_every_credential_value(tmp_path: Path) -> None:
    append_config_event(
        tmp_path,
        connector_id="github-security",
        state="disabled",
        actor="admin@example.test",
        credentials=dict(SECRETS, host="https://api.github.example", token_ref="env:GH_TOKEN"),
        options={},
    )
    entries = build_audit_log(tmp_path, category="connector")
    blob = json.dumps(entries)
    for value in SECRETS.values():
        assert value.split()[-1] not in blob
    credentials = entries[0]["payload"]["credentials"]
    assert set(credentials) == {*SECRETS, "host", "token_ref"}
    assert all(isinstance(v, str) and v.startswith("***") for v in credentials.values())


def test_audit_log_masks_credentials_already_persisted_in_plaintext(tmp_path: Path) -> None:
    gold = tmp_path / "gold"
    gold.mkdir()
    row = {
        "connector_id": "iceberg-parquet-lake",
        "state": "disabled",
        "actor": "admin",
        "occurred_at": "2026-10-01T00:00:00Z",
        "credentials": {"uri": "https://svc:SEKRET_URIPW@cat.example", "apikey": "SEKRET_OLD"},
    }
    (gold / "connector_config.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    blob = json.dumps(build_audit_log(tmp_path, category="connector"))
    assert "SEKRET_URIPW" not in blob
    assert "SEKRET_OLD" not in blob


@pytest.mark.parametrize(
    "credentials",
    [
        {"uri": "https://svc:pw@cat.example"},
        {"host": "https://user@ch.example:8443"},
        {"nested": {"base_url": "http://a:b@x.example/path"}},
    ],
)
def test_configure_rejects_urls_with_userinfo(credentials: dict) -> None:
    error = configure_payload_error(
        connector_id="iceberg-parquet-lake", state="disabled", credentials=credentials, options={}
    )
    assert error is not None
    assert "user" in error.lower() and "url" in error.lower()


def test_configure_accepts_urls_without_userinfo() -> None:
    assert (
        configure_payload_error(
            connector_id="iceberg-parquet-lake",
            state="disabled",
            credentials={"uri": "https://cat.example/api?x=1", "warehouse": "w"},
            options={},
        )
        is None
    )


def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, str, str]:
    monkeypatch.setenv("TRUSTOPS_COOKIE_SIGNING_KEY", "x" * 48)
    app = create_app(tmp_path)
    with app.state.sessionmaker() as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        admin = create_user(session, tenant_id=tenant.id, email="admin@acme.test", role="admin")
        _k, admin_token = create_api_key(session, tenant_id=tenant.id, user_id=admin.id)
        reader = create_user(session, tenant_id=tenant.id, email="ro@acme.test", role="read_only")
        _k, reader_token = create_api_key(session, tenant_id=tenant.id, user_id=reader.id)
        session.commit()
    return TestClient(app, base_url="https://testserver"), admin_token, reader_token


def test_read_only_audit_log_never_returns_connector_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, admin_token, reader_token = _server(tmp_path, monkeypatch)
    resp = client.post(
        "/api/v1/connectors/iceberg-parquet-lake/configure",
        headers=_bearer(admin_token),
        json={"state": "disabled", "credentials": {"catalog_type": "rest", "warehouse": "w", **SECRETS}},
    )
    assert resp.status_code == 201
    for path in ("/api/v1/audit-log?category=connector", "/api/audit-log"):
        body = client.get(path, headers=_bearer(reader_token)).text
        for value in SECRETS.values():
            assert value.split()[-1] not in body, path


def test_configure_api_rejects_uri_userinfo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, admin_token, _reader = _server(tmp_path, monkeypatch)
    resp = client.post(
        "/api/v1/connectors/iceberg-parquet-lake/configure",
        headers=_bearer(admin_token),
        json={"state": "disabled", "credentials": {"catalog_type": "rest", "uri": "https://svc:SEKRET@cat.example"}},
    )
    assert resp.status_code == 400
    assert "SEKRET" not in resp.text
    assert (
        not (tmp_path / "gold" / "connector_config.jsonl").exists()
        or "SEKRET" not in (tmp_path / "gold" / "connector_config.jsonl").read_text()
    )
