"""Signed session cookie helpers."""

from __future__ import annotations

import pytest

from security_lakehouse.auth.sessions import (
    decode_session_cookie,
    encode_session_cookie,
    ensure_cookie_signing_configured,
    generate_session_token,
)


def test_encode_decode_roundtrip(monkeypatch) -> None:
    monkeypatch.setenv("GRC_LAKE_COOKIE_SIGNING_KEY", "roundtrip-signing-key")
    token, _digest = generate_session_token()
    signed = encode_session_cookie(token)
    assert signed != token
    assert decode_session_cookie(signed) == token


def test_decode_rejects_unsigned_token(monkeypatch) -> None:
    monkeypatch.setenv("GRC_LAKE_COOKIE_SIGNING_KEY", "roundtrip-signing-key")
    token, _digest = generate_session_token()
    assert decode_session_cookie(token) is None


def test_decode_rejects_tampered_cookie(monkeypatch) -> None:
    monkeypatch.setenv("GRC_LAKE_COOKIE_SIGNING_KEY", "roundtrip-signing-key")
    token, _digest = generate_session_token()
    signed = encode_session_cookie(token)
    assert decode_session_cookie(signed + "x") is None


def test_ensure_cookie_signing_configured_requires_key(monkeypatch) -> None:
    monkeypatch.delenv("GRC_LAKE_COOKIE_SIGNING_KEY", raising=False)
    with pytest.raises(RuntimeError, match="GRC_LAKE_COOKIE_SIGNING_KEY"):
        ensure_cookie_signing_configured()


def test_decode_rejects_non_session_payload(monkeypatch) -> None:
    monkeypatch.setenv("GRC_LAKE_COOKIE_SIGNING_KEY", "roundtrip-signing-key")
    signed = encode_session_cookie("not-a-session-token")
    assert decode_session_cookie(signed) is None
