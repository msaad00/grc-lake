"""OIDC auto-provisioning only admits emails from operator-allowed domains."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from security_lakehouse.auth.oidc import OIDCConfig, OIDCLoginError, complete_oidc_login, load_oidc_config
from security_lakehouse.db import repository
from security_lakehouse.db.base import session_scope
from security_lakehouse.db.repository import create_tenant, create_user
from security_lakehouse.server_app import create_app


def _config(allowed: frozenset[str]) -> OIDCConfig:
    return OIDCConfig(
        issuer="https://idp.test",
        client_id="cid",
        client_secret="sec",
        tenant_slug="acme",
        auto_provision=True,
        allowed_domains=allowed,
    )


@pytest.fixture
def factory(tmp_path: Path):
    app = create_app(tmp_path, require_auth=False)
    with session_scope(app.state.sessionmaker) as session:
        create_tenant(session, slug="acme", name="Acme")
    return app.state.sessionmaker


def test_load_oidc_config_parses_allowed_domains(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_OIDC_ISSUER", "https://idp.test")
    monkeypatch.setenv("TRUSTOPS_OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("TRUSTOPS_OIDC_CLIENT_SECRET", "sec")
    monkeypatch.setenv("TRUSTOPS_OIDC_ALLOWED_DOMAINS", " Acme.test, @corp.example ,,")
    config = load_oidc_config()
    assert config is not None
    assert config.allowed_domains == frozenset({"acme.test", "corp.example"})


def test_auto_provision_refuses_email_outside_allowlist(factory) -> None:
    with session_scope(factory) as session:
        with pytest.raises(OIDCLoginError, match="not allowed"):
            complete_oidc_login(
                session,
                config=_config(frozenset({"acme.test"})),
                email="random.stranger@gmail.com",
                email_verified=True,
            )
        with pytest.raises(OIDCLoginError):
            complete_oidc_login(
                session,
                config=_config(frozenset({"acme.test"})),
                email="eve@evil.acme.test",
                email_verified=True,
            )
        assert repository.get_tenant_by_slug(session, slug="acme") is not None
        tenant = repository.get_tenant_by_slug(session, slug="acme")
        assert repository.get_user_by_email(session, tenant_id=tenant.id, email="random.stranger@gmail.com") is None


def test_auto_provision_admits_allowlisted_domain_case_insensitively(factory) -> None:
    with session_scope(factory) as session:
        user, _token = complete_oidc_login(
            session, config=_config(frozenset({"acme.test"})), email="New@ACME.test", email_verified=True
        )
        assert user.role == "read_only"


def test_auto_provision_without_allowlist_fails_closed(factory) -> None:
    with session_scope(factory) as session, pytest.raises(OIDCLoginError, match="GRC_LAKE_OIDC_ALLOWED_DOMAINS"):
        complete_oidc_login(session, config=_config(frozenset()), email="new@acme.test", email_verified=True)


def test_existing_user_signs_in_regardless_of_allowlist(factory) -> None:
    with session_scope(factory) as session:
        tenant = repository.get_tenant_by_slug(session, slug="acme")
        create_user(session, tenant_id=tenant.id, email="contractor@partner.example")
        user, _token = complete_oidc_login(
            session,
            config=_config(frozenset({"acme.test"})),
            email="contractor@partner.example",
            email_verified=True,
        )
        assert user.email == "contractor@partner.example"


def test_startup_logs_error_when_auto_provision_has_no_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("TRUSTOPS_OIDC_ISSUER", "https://idp.test")
    monkeypatch.setenv("TRUSTOPS_OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("TRUSTOPS_OIDC_CLIENT_SECRET", "sec")
    monkeypatch.setenv("TRUSTOPS_SESSION_SECRET", "s" * 48)
    monkeypatch.setenv("TRUSTOPS_OIDC_AUTO_PROVISION", "true")
    monkeypatch.delenv("TRUSTOPS_OIDC_ALLOWED_DOMAINS", raising=False)
    with caplog.at_level(logging.ERROR):
        create_app(tmp_path, require_auth=False)
    assert any("GRC_LAKE_OIDC_ALLOWED_DOMAINS" in record.getMessage() for record in caplog.records)
