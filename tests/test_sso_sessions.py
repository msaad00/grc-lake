"""Browser session + OIDC login tests for server mode.

The OIDC redirect/token-exchange is driven by an external identity provider, so
the network flow is not unit-tested here. The provisioning + session issuance
logic (:func:`complete_oidc_login`) and the session-cookie auth path are.
"""

from __future__ import annotations

from datetime import UTC, datetime
from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient  # noqa: E402

from security_lakehouse.auth.oidc import OIDCConfig, OIDCLoginError, complete_oidc_login  # noqa: E402
from security_lakehouse.auth.saml import (  # noqa: E402
    SAML_REQUEST_COOKIE,
    AssertionReplayCache,
    SAMLConfig,
    SAMLConfigError,
    SAMLLoginError,
    complete_saml_login,
    load_saml_config,
    saml_request_data,
)
from security_lakehouse.auth.sessions import SESSION_COOKIE, encode_session_cookie  # noqa: E402
from security_lakehouse.db import repository  # noqa: E402
from security_lakehouse.db.base import session_scope  # noqa: E402
from security_lakehouse.db.repository import create_tenant, create_user, create_user_session  # noqa: E402
from security_lakehouse.server_app import create_app  # noqa: E402
from test_api_v1 import _seed_lake  # noqa: E402


def _config(*, tenant_slug: str = "acme", auto_provision: bool = False) -> OIDCConfig:
    return OIDCConfig(
        issuer="https://idp.test",
        client_id="cid",
        client_secret="sec",
        tenant_slug=tenant_slug,
        auto_provision=auto_provision,
        allowed_domains=frozenset({"acme.test"}),
    )


def _saml_config(*, tenant_slug: str = "acme", auto_provision: bool = False) -> SAMLConfig:
    return SAMLConfig(
        sp_entity_id="https://trustops.test/saml/metadata",
        acs_url="https://trustops.test/api/v1/auth/saml/acs",
        idp_entity_id="https://idp.test",
        idp_sso_url="https://idp.test/sso",
        idp_x509_cert="cert",
        tenant_slug=tenant_slug,
        auto_provision=auto_provision,
    )


@pytest.fixture
def app_env(tmp_path: Path):
    _seed_lake(tmp_path)
    app = create_app(tmp_path)  # auth required; OIDC not configured
    return app, TestClient(app)


def test_session_repository_lifecycle(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        user = create_user(session, tenant_id=tenant.id, email="u@acme.test", role="read_only")
        row, token = create_user_session(session, tenant_id=tenant.id, user_id=user.id)
        assert row.is_active()
    with session_scope(app.state.sessionmaker) as session:
        assert repository.resolve_user_session(session, token).is_active()
        assert repository.revoke_user_session(session, token, now=datetime.now(UTC))
    with session_scope(app.state.sessionmaker) as session:
        assert not repository.resolve_user_session(session, token).is_active()


def test_expired_session_is_inactive(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        user = create_user(session, tenant_id=tenant.id, email="u@acme.test")
        row, _token = create_user_session(session, tenant_id=tenant.id, user_id=user.id, ttl_hours=-1)
        assert not row.is_active()


def test_complete_oidc_login_requires_provisioned_user(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        create_tenant(session, slug="acme", name="Acme")
        with pytest.raises(OIDCLoginError):
            complete_oidc_login(
                session,
                config=_config(auto_provision=False),
                email="new@acme.test",
                email_verified=True,
            )


def test_complete_oidc_login_rejects_unverified_email(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        create_tenant(session, slug="acme", name="Acme")
        with pytest.raises(OIDCLoginError, match="not verified"):
            complete_oidc_login(
                session,
                config=_config(auto_provision=True),
                email="new@acme.test",
                email_verified=False,
            )


def test_complete_oidc_login_auto_provisions(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        create_tenant(session, slug="acme", name="Acme")
        user, token = complete_oidc_login(
            session,
            config=_config(auto_provision=True),
            email="new@acme.test",
            email_verified=True,
        )
        assert user.email == "new@acme.test"
        assert user.role == "read_only"
        assert repository.resolve_user_session(session, token).is_active()


def test_complete_oidc_login_maps_idp_groups_to_role(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GRC_LAKE_IDP_SYNC_ROLE_ON_LOGIN", "1")
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    cfg = OIDCConfig(
        issuer="https://idp.test",
        client_id="cid",
        client_secret="sec",
        tenant_slug="acme",
        auto_provision=True,
        default_role="read_only",
        role_map={"GRC Lake-Admins": "admin"},
        allowed_domains=frozenset({"acme.test"}),
    )
    with session_scope(app.state.sessionmaker) as session:
        create_tenant(session, slug="acme", name="Acme")
        user, _token = complete_oidc_login(
            session,
            config=cfg,
            email="mapped@acme.test",
            email_verified=True,
            idp_claim_values=["GRC Lake-Admins"],
        )
        assert user.role == "admin"
        user2, _token2 = complete_oidc_login(
            session,
            config=cfg,
            email="mapped@acme.test",
            email_verified=True,
            idp_claim_values=["Staff"],
        )
        assert user2.role == "read_only"


def test_complete_oidc_login_unknown_tenant(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session, pytest.raises(OIDCLoginError):
        complete_oidc_login(
            session,
            config=_config(tenant_slug="ghost", auto_provision=True),
            email="x@y.test",
            email_verified=True,
        )


def test_session_cookie_authenticates(app_env) -> None:
    app, client = app_env
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        user = create_user(session, tenant_id=tenant.id, email="u@acme.test", role="read_only")
        _row, token = create_user_session(session, tenant_id=tenant.id, user_id=user.id)
    client.cookies.set(SESSION_COOKIE, encode_session_cookie(token))
    assert client.get("/api/v1/controls").status_code == HTTPStatus.OK
    who = client.get("/api/v1/auth/whoami").json()["data"]
    assert who["email"] == "u@acme.test"
    assert who["role"] == "read_only"


def test_logout_revokes_session(app_env) -> None:
    app, client = app_env
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        user = create_user(session, tenant_id=tenant.id, email="u@acme.test")
        _row, token = create_user_session(session, tenant_id=tenant.id, user_id=user.id)
    signed = encode_session_cookie(token)
    client.cookies.set(SESSION_COOKIE, signed)
    assert client.post("/api/v1/auth/logout", json={}).status_code == HTTPStatus.OK
    client.cookies.set(SESSION_COOKIE, signed)  # re-present the now-revoked token
    assert client.get("/api/v1/controls").status_code == HTTPStatus.UNAUTHORIZED


def test_login_501_when_oidc_unconfigured(app_env) -> None:
    _app, client = app_env
    assert client.get("/api/v1/auth/login").status_code == HTTPStatus.NOT_IMPLEMENTED


def test_auth_methods_reports_configured_login_surfaces(app_env) -> None:
    app, client = app_env
    app.state.oauth = object()
    app.state.oidc_config = _config()
    app.state.saml_config = _saml_config()

    resp = client.get("/api/v1/auth/methods")
    assert resp.status_code == HTTPStatus.OK
    body = resp.json()["data"]
    assert body["require_auth"] is True
    methods = {method["id"]: method for method in body["methods"]}
    assert methods["oidc"]["configured"] is True
    assert methods["oidc"]["login_url"] == "/api/v1/auth/login"
    assert methods["oidc"]["protocol"] == "OIDC"
    assert methods["saml"]["configured"] is True
    assert methods["saml"]["login_url"] == "/api/v1/auth/saml/login"
    assert methods["saml"]["protocol"] == "SAML 2.0"
    assert methods["api_key"]["configured"] is True
    assert methods["api_key"]["login_url"] == "/api/v1/auth/session-from-key"


def test_load_saml_config_rejects_partial_environment(monkeypatch) -> None:
    monkeypatch.setenv("GRC_LAKE_SAML_SP_ENTITY_ID", "https://trustops.test/saml/metadata")
    with pytest.raises(SAMLConfigError):
        load_saml_config()


def test_saml_request_data_parses_post_body() -> None:
    data = saml_request_data(
        scheme="https",
        host="trustops.test",
        port=443,
        path="/api/v1/auth/saml/acs",
        query={"RelayState": "/console"},
        body=b"SAMLResponse=abc%2B123&RelayState=%2Fconsole",
    )
    assert data["https"] == "on"
    assert data["post_data"]["SAMLResponse"] == "abc+123"
    assert data["post_data"]["RelayState"] == "/console"


def test_complete_saml_login_auto_provisions(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        create_tenant(session, slug="acme", name="Acme")
        user, token = complete_saml_login(
            session,
            config=_saml_config(auto_provision=True),
            email="saml@acme.test",
        )
        assert user.email == "saml@acme.test"
        assert user.role == "read_only"
        resolved = repository.resolve_user_session(session, token)
        assert resolved.is_active()
        assert resolved.idp == "saml"


def test_complete_saml_login_requires_provisioned_user(tmp_path: Path) -> None:
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        create_tenant(session, slug="acme", name="Acme")
        with pytest.raises(SAMLLoginError):
            complete_saml_login(session, config=_saml_config(auto_provision=False), email="new@acme.test")


def test_saml_login_501_when_unconfigured(app_env) -> None:
    _app, client = app_env
    assert client.get("/api/v1/auth/saml/login").status_code == HTTPStatus.NOT_IMPLEMENTED
    assert client.post("/api/v1/auth/saml/acs").status_code == HTTPStatus.NOT_IMPLEMENTED


class _FakeSamlSettings:
    def get_sp_metadata(self) -> str:
        return "<EntityDescriptor />"

    def validate_metadata(self, metadata: str) -> list[str]:
        return []


class _FakeSamlAuth:
    """Mimics python3-saml: InResponseTo is only checked when both sides are present."""

    def __init__(
        self,
        email: str = "saml@acme.test",
        authenticated: bool = True,
        *,
        request_id: str = "ONELOGIN_req-1",
        in_response_to: str | None = "ONELOGIN_req-1",
        assertion_id: str = "_assertion-1",
        not_on_or_after: int | None = None,
        seen: list[str | None] | None = None,
    ) -> None:
        self.email = email
        self.authenticated = authenticated
        self.request_id = request_id
        self.in_response_to = in_response_to
        self.assertion_id = assertion_id
        self.not_on_or_after = not_on_or_after
        self.seen = seen if seen is not None else []
        self._errors: list[str] = []

    def login(self) -> str:
        return "https://idp.test/sso?SAMLRequest=fake"

    def get_last_request_id(self) -> str:
        return self.request_id

    def process_response(self, request_id: str | None = None) -> None:
        self.seen.append(request_id)
        mismatched = self.in_response_to is not None and request_id is not None and self.in_response_to != request_id
        if not self.authenticated or mismatched:
            self._errors = ["invalid_response"]

    def get_errors(self) -> list[str]:
        return self._errors

    def is_authenticated(self) -> bool:
        return self.authenticated and not self._errors

    def get_last_response_in_response_to(self) -> str | None:
        return self.in_response_to

    def get_last_assertion_id(self) -> str:
        return self.assertion_id

    def get_last_assertion_not_on_or_after(self) -> int | None:
        return self.not_on_or_after

    def get_attributes(self) -> dict[str, list[str]]:
        return {"email": [self.email]}

    def get_nameid(self) -> str:
        return self.email

    def get_settings(self) -> _FakeSamlSettings:
        return _FakeSamlSettings()


def _set_saml_env(monkeypatch) -> None:
    monkeypatch.setenv("GRC_LAKE_SAML_SP_ENTITY_ID", "https://trustops.test/saml/metadata")
    monkeypatch.setenv("GRC_LAKE_SAML_ACS_URL", "https://trustops.test/api/v1/auth/saml/acs")
    monkeypatch.setenv("GRC_LAKE_SAML_IDP_ENTITY_ID", "https://idp.test")
    monkeypatch.setenv("GRC_LAKE_SAML_IDP_SSO_URL", "https://idp.test/sso")
    monkeypatch.setenv("GRC_LAKE_SAML_IDP_X509_CERT", "cert")
    monkeypatch.setenv("GRC_LAKE_SAML_TENANT_SLUG", "acme")
    monkeypatch.setenv("GRC_LAKE_SAML_AUTO_PROVISION", "true")


def _saml_app(tmp_path: Path, monkeypatch, **fake_kwargs):
    _set_saml_env(monkeypatch)
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    seen: list[str | None] = []
    app.state.saml_auth_factory = lambda _config, _request_data: _FakeSamlAuth(seen=seen, **fake_kwargs)
    with session_scope(app.state.sessionmaker) as session:
        create_tenant(session, slug="acme", name="Acme")
    return app, seen


def _post_acs(client, request_cookie: str | None = None):
    if request_cookie is not None:
        client.cookies.set(SAML_REQUEST_COOKIE, request_cookie)
    else:
        client.cookies.clear()
    return client.post(
        "/api/v1/auth/saml/acs",
        content=b"SAMLResponse=fake",
        headers={"content-type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )


def _login_request_cookie(client) -> str:
    login = client.get("/api/v1/auth/saml/login", follow_redirects=False)
    assert login.status_code == HTTPStatus.FOUND
    header = next(v for k, v in login.headers.multi_items() if k == "set-cookie" and SAML_REQUEST_COOKIE in v)
    return header.split(f"{SAML_REQUEST_COOKIE}=", 1)[1].split(";", 1)[0]


def test_saml_endpoints_use_same_session_model(tmp_path: Path, monkeypatch) -> None:
    app, seen = _saml_app(tmp_path, monkeypatch)
    client = TestClient(app)

    login = client.get("/api/v1/auth/saml/login", follow_redirects=False)
    assert login.status_code == HTTPStatus.FOUND
    assert login.headers["location"].startswith("https://idp.test/sso")

    metadata = client.get("/api/v1/auth/saml/metadata")
    assert metadata.status_code == HTTPStatus.OK
    assert "EntityDescriptor" in metadata.text

    acs = _post_acs(client, _login_request_cookie(client))
    assert acs.status_code == HTTPStatus.FOUND
    assert SESSION_COOKIE in acs.headers["set-cookie"]
    assert seen[-1] == "ONELOGIN_req-1"  # the AuthnRequest ID reached process_response

    session_token = acs.headers["set-cookie"].split(f"{SESSION_COOKIE}=", 1)[1].split(";", 1)[0]
    client.cookies.clear()
    client.cookies.set(SESSION_COOKIE, session_token)
    who = client.get("/api/v1/auth/whoami").json()["data"]
    assert who["email"] == "saml@acme.test"
    assert who["role"] == "read_only"


def test_saml_login_request_cookie_is_signed_and_cross_site_postable(tmp_path: Path, monkeypatch) -> None:
    app, _seen = _saml_app(tmp_path, monkeypatch)
    client = TestClient(app)
    login = client.get("/api/v1/auth/saml/login", follow_redirects=False)
    header = next(v for k, v in login.headers.multi_items() if k == "set-cookie" and SAML_REQUEST_COOKIE in v)
    assert "ONELOGIN_req-1" not in header  # signed, not the bare id
    lowered = header.lower()
    assert "httponly" in lowered
    assert "samesite=none" in lowered and "secure" in lowered  # the IdP POSTs cross-site


def test_saml_acs_rejects_a_replayed_assertion(tmp_path: Path, monkeypatch) -> None:
    app, _seen = _saml_app(tmp_path, monkeypatch)
    client = TestClient(app)
    cookie = _login_request_cookie(client)

    assert _post_acs(client, cookie).status_code == HTTPStatus.FOUND
    replay = _post_acs(client, cookie)
    assert replay.status_code == HTTPStatus.UNAUTHORIZED


def test_saml_acs_rejects_unsolicited_response_by_default(tmp_path: Path, monkeypatch) -> None:
    app, _seen = _saml_app(tmp_path, monkeypatch, in_response_to=None)
    client = TestClient(app)
    assert _post_acs(client).status_code == HTTPStatus.UNAUTHORIZED


def test_saml_acs_rejects_forged_request_cookie(tmp_path: Path, monkeypatch) -> None:
    app, _seen = _saml_app(tmp_path, monkeypatch)
    client = TestClient(app)
    assert _post_acs(client, "ONELOGIN_req-1").status_code == HTTPStatus.UNAUTHORIZED


def test_saml_acs_requires_in_response_to_when_sp_initiated(tmp_path: Path, monkeypatch) -> None:
    """python3-saml skips the InResponseTo check when the response omits it;
    an SP-initiated login must not accept a response that answers no request."""
    app, _seen = _saml_app(tmp_path, monkeypatch, in_response_to=None)
    client = TestClient(app)
    assert _post_acs(client, _login_request_cookie(client)).status_code == HTTPStatus.UNAUTHORIZED


def test_saml_acs_rejects_response_to_a_different_request(tmp_path: Path, monkeypatch) -> None:
    app, _seen = _saml_app(tmp_path, monkeypatch, in_response_to="ONELOGIN_other")
    client = TestClient(app)
    assert _post_acs(client, _login_request_cookie(client)).status_code == HTTPStatus.UNAUTHORIZED


def test_saml_idp_initiated_login_is_opt_in_and_still_replay_protected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GRC_LAKE_SAML_ALLOW_IDP_INITIATED", "true")
    app, seen = _saml_app(tmp_path, monkeypatch, in_response_to=None)
    client = TestClient(app)

    assert _post_acs(client).status_code == HTTPStatus.FOUND
    assert seen[-1] is None
    assert _post_acs(client).status_code == HTTPStatus.UNAUTHORIZED


def test_assertion_replay_cache_expires_and_is_bounded() -> None:
    cache = AssertionReplayCache(max_entries=2, default_ttl_seconds=60)
    assert cache.check_and_store("a", not_on_or_after=None, now=1000.0) is True
    assert cache.check_and_store("a", not_on_or_after=None, now=1001.0) is False
    # Past its NotOnOrAfter the id can no longer validate, so it may be forgotten.
    assert cache.check_and_store("b", not_on_or_after=1010, now=1002.0) is True
    assert cache.check_and_store("b", not_on_or_after=1010, now=1011.0) is True
    assert cache.check_and_store("c", not_on_or_after=None, now=1012.0) is True
    assert cache.check_and_store("d", not_on_or_after=None, now=1013.0) is True
    assert len(cache) <= 2


def test_saml_acs_rejects_a_replay_on_another_replica(tmp_path: Path, monkeypatch) -> None:
    """Two app instances on one database stand in for two replicas behind a load balancer."""
    replica_a, _seen = _saml_app(tmp_path, monkeypatch)
    replica_b = create_app(tmp_path)
    replica_b.state.saml_auth_factory = replica_a.state.saml_auth_factory
    client_a = TestClient(replica_a)
    client_b = TestClient(replica_b)

    assert _post_acs(client_a, _login_request_cookie(client_a)).status_code == HTTPStatus.FOUND
    replay = _post_acs(client_b, _login_request_cookie(client_b))
    assert replay.status_code == HTTPStatus.UNAUTHORIZED


def _replay_store(tmp_path: Path):
    from security_lakehouse.db import migrate
    from security_lakehouse.db.base import create_engine_for, session_factory

    migrate.upgrade(tmp_path)
    return session_factory(create_engine_for(tmp_path))


def _replay_rows(factory) -> list[tuple[str, str]]:
    from sqlalchemy import select

    from security_lakehouse.db.models import SamlAssertionReplay

    with factory() as session:
        return [
            (row.issuer, row.assertion_id)
            for row in session.scalars(select(SamlAssertionReplay).order_by(SamlAssertionReplay.assertion_id))
        ]


def test_database_replay_cache_rejects_a_consumed_assertion(tmp_path: Path) -> None:
    from security_lakehouse.auth.saml import DatabaseAssertionReplayCache

    factory = _replay_store(tmp_path)
    cache = DatabaseAssertionReplayCache(factory)
    assert cache.check_and_store("_a1", not_on_or_after=2000, issuer="https://idp.test", now=1000.0) is True
    assert cache.check_and_store("_a1", not_on_or_after=2000, issuer="https://idp.test", now=1001.0) is False
    # IDs are unique per issuer, so another IdP's identical id is a different assertion.
    assert cache.check_and_store("_a1", not_on_or_after=2000, issuer="https://other-idp.test", now=1002.0) is True
    assert _replay_rows(factory) == [("https://idp.test", "_a1"), ("https://other-idp.test", "_a1")]


def test_database_replay_cache_is_shared_between_instances(tmp_path: Path) -> None:
    from security_lakehouse.auth.saml import DatabaseAssertionReplayCache

    factory = _replay_store(tmp_path)
    replica_a = DatabaseAssertionReplayCache(factory)
    replica_b = DatabaseAssertionReplayCache(factory)
    assert replica_a.check_and_store("_a1", not_on_or_after=2000, issuer="idp", now=1000.0) is True
    assert replica_b.check_and_store("_a1", not_on_or_after=2000, issuer="idp", now=1001.0) is False


def test_database_replay_cache_forgets_expired_ids_and_cleans_up(tmp_path: Path) -> None:
    from security_lakehouse.auth.saml import DatabaseAssertionReplayCache

    factory = _replay_store(tmp_path)
    cache = DatabaseAssertionReplayCache(factory, default_ttl_seconds=60, cleanup_interval_seconds=100)
    assert cache.check_and_store("_old", not_on_or_after=1010, issuer="idp", now=1000.0) is True
    assert cache.check_and_store("_ttl", not_on_or_after=None, issuer="idp", now=1000.0) is True
    # Past NotOnOrAfter the assertion no longer validates, so its id may be reused.
    assert cache.check_and_store("_old", not_on_or_after=1100, issuer="idp", now=1011.0) is True
    # The default TTL applies when the assertion carries no NotOnOrAfter.
    assert cache.check_and_store("_ttl", not_on_or_after=None, issuer="idp", now=1059.0) is False
    # The periodic sweep drops every expired row, not only the one being checked.
    assert cache.check_and_store("_new", not_on_or_after=5000, issuer="idp", now=1200.0) is True
    assert _replay_rows(factory) == [("idp", "_new")]


def test_database_replay_cache_concurrent_insert_admits_exactly_one(tmp_path: Path) -> None:
    import threading

    from security_lakehouse.auth.saml import DatabaseAssertionReplayCache

    factory = _replay_store(tmp_path)
    workers = 8
    barrier = threading.Barrier(workers)
    results: list[bool] = []
    lock = threading.Lock()

    def consume() -> None:
        cache = DatabaseAssertionReplayCache(factory)  # one per "replica"
        barrier.wait()
        ok = cache.check_and_store("_race", not_on_or_after=None, issuer="idp")
        with lock:
            results.append(ok)

    threads = [threading.Thread(target=consume) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == [False] * (workers - 1) + [True]
    assert _replay_rows(factory) == [("idp", "_race")]


def test_database_replay_cache_fails_closed_when_the_store_errors(tmp_path: Path) -> None:
    from sqlalchemy.exc import OperationalError

    from security_lakehouse.auth.saml import DatabaseAssertionReplayCache

    def broken_factory():
        raise OperationalError("INSERT", {}, Exception("database is unavailable"))

    cache = DatabaseAssertionReplayCache(broken_factory)
    assert cache.check_and_store("_a1", not_on_or_after=None, issuer="idp") is False


def test_saml_replay_migration_adds_unique_table_and_downgrades(tmp_path: Path) -> None:
    from alembic import command
    from sqlalchemy import inspect

    from security_lakehouse.db import migrate
    from security_lakehouse.db.base import create_engine_for, database_url

    migrate.upgrade(tmp_path)
    engine = create_engine_for(tmp_path)
    inspector = inspect(engine)
    assert "saml_assertion_replays" in inspector.get_table_names()
    uniques = inspector.get_unique_constraints("saml_assertion_replays")
    assert any(sorted(u["column_names"]) == ["assertion_id", "issuer"] for u in uniques)
    assert any(ix["column_names"] == ["expires_at"] for ix in inspector.get_indexes("saml_assertion_replays"))
    engine.dispose()

    command.downgrade(migrate._config(database_url(tmp_path)), "0019_task_resolution_note")
    engine = create_engine_for(tmp_path)
    assert "saml_assertion_replays" not in inspect(engine).get_table_names()
    engine.dispose()


def test_saml_acs_rejects_failed_response(tmp_path: Path, monkeypatch) -> None:
    app, _seen = _saml_app(tmp_path, monkeypatch, authenticated=False)
    client = TestClient(app)
    resp = _post_acs(client, _login_request_cookie(client))
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
