"""Server-mode security guardrails."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from security_lakehouse.auth.oidc import OIDCConfig
from security_lakehouse.server_app import create_app
from test_api_v1 import _seed_lake


def test_insecure_no_auth_blocked_in_production(tmp_path: Path, monkeypatch) -> None:
    _seed_lake(tmp_path)
    monkeypatch.setenv("TRUSTOPS_ALLOW_INSECURE_NO_AUTH", "1")
    monkeypatch.setenv("TRUSTOPS_ENV", "production")
    with pytest.raises(RuntimeError, match="forbidden"):
        create_app(tmp_path)


def test_oidc_requires_session_secret(tmp_path: Path, monkeypatch) -> None:
    _seed_lake(tmp_path)
    monkeypatch.setenv("TRUSTOPS_OIDC_ISSUER", "https://idp.test")
    monkeypatch.setenv("TRUSTOPS_OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("TRUSTOPS_OIDC_CLIENT_SECRET", "sec")
    monkeypatch.setenv("TRUSTOPS_COOKIE_SIGNING_KEY", "test-cookie-signing-key")
    monkeypatch.delenv("TRUSTOPS_SESSION_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="TRUSTOPS_SESSION_SECRET"):
        create_app(tmp_path)


def test_auth_requires_cookie_signing_key(tmp_path: Path, monkeypatch) -> None:
    _seed_lake(tmp_path)
    monkeypatch.delenv("TRUSTOPS_COOKIE_SIGNING_KEY", raising=False)
    with pytest.raises(RuntimeError, match="TRUSTOPS_COOKIE_SIGNING_KEY"):
        create_app(tmp_path)


def test_oidc_starts_when_session_secret_set(tmp_path: Path, monkeypatch) -> None:
    _seed_lake(tmp_path)
    monkeypatch.setenv("TRUSTOPS_OIDC_ISSUER", "https://idp.test")
    monkeypatch.setenv("TRUSTOPS_OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("TRUSTOPS_OIDC_CLIENT_SECRET", "sec")
    monkeypatch.setenv("TRUSTOPS_SESSION_SECRET", "test-session-secret")
    monkeypatch.setenv("TRUSTOPS_COOKIE_SIGNING_KEY", "test-cookie-signing-key")
    app = create_app(tmp_path)
    assert isinstance(app.state.oidc_config, OIDCConfig)
