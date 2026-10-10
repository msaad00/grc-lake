"""Cookie signatures use explicit SHA-256 and reject undersized secrets."""

from __future__ import annotations

import hashlib

import pytest
from itsdangerous import URLSafeTimedSerializer

from security_lakehouse.auth.saml import decode_saml_request_id, encode_saml_request_id
from security_lakehouse.auth.sessions import (
    decode_session_cookie,
    encode_session_cookie,
    ensure_cookie_signing_configured,
)

KEY = "test-only-key-with-at-least-32-bytes"


@pytest.mark.parametrize("key", ["x", "x" * 31, "  short  "])
def test_short_cookie_keys_fail_closed(monkeypatch, key: str) -> None:
    monkeypatch.setenv("GRC_LAKE_COOKIE_SIGNING_KEY", key)
    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        ensure_cookie_signing_configured()
    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        encode_session_cookie("tops_sess_" + "a" * 64)
    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        encode_saml_request_id("request-1")


@pytest.mark.parametrize(
    ("encode", "decode", "salt", "payload"),
    [
        (encode_session_cookie, decode_session_cookie, "trustops-session-cookie", "tops_sess_" + "a" * 64),
        (encode_saml_request_id, decode_saml_request_id, "trustops-saml-authn-request", "request-1"),
    ],
)
def test_cookie_sha256_roundtrip_and_legacy_sha1_rejection(monkeypatch, encode, decode, salt, payload) -> None:
    monkeypatch.setenv("GRC_LAKE_COOKIE_SIGNING_KEY", KEY)
    sha256 = URLSafeTimedSerializer(KEY, salt=salt, signer_kwargs={"digest_method": hashlib.sha256})
    assert sha256.loads(encode(payload)) == payload
    assert decode(sha256.dumps(payload)) == payload
    sha1 = URLSafeTimedSerializer(KEY, salt=salt, signer_kwargs={"digest_method": hashlib.sha1})
    assert decode(sha1.dumps(payload)) is None


@pytest.mark.parametrize("secret", ["short", KEY])
def test_oidc_signing_policy_is_wired_into_app(tmp_path, monkeypatch, secret: str) -> None:
    from starlette.middleware.sessions import SessionMiddleware

    from security_lakehouse.server_app import create_app

    monkeypatch.setenv("GRC_LAKE_COOKIE_SIGNING_KEY", KEY)
    monkeypatch.setenv("GRC_LAKE_OIDC_ISSUER", "https://idp.test")
    monkeypatch.setenv("GRC_LAKE_OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("GRC_LAKE_OIDC_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("GRC_LAKE_SESSION_SECRET", secret)
    if secret == "short":
        with pytest.raises(RuntimeError, match="GRC_LAKE_SESSION_SECRET.*at least 32 bytes"):
            create_app(tmp_path)
        return
    app = create_app(tmp_path)
    layer = next(layer for layer in app.user_middleware if issubclass(layer.cls, SessionMiddleware))
    middleware = layer.cls(app, **layer.kwargs)
    assert middleware.signer.digest_method().name == "sha256"
    assert middleware.security_flags == "httponly; samesite=lax; secure"
