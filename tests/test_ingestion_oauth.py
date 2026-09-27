"""OAuth 2.0 client-credentials token source shared by API connectors."""

from __future__ import annotations

import email.message
import io
import json
import urllib.error
import urllib.parse
from typing import Any

import pytest

from security_lakehouse import netguard
from security_lakehouse.ingestion.oauth import ClientCredentialsToken, CredentialRejectedError

TOKEN_URL = "https://idp.example.com/oauth/token"


class _FakeResponse(io.BytesIO):
    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _http_error(url: str, code: int, headers: dict[str, str] | None = None) -> urllib.error.HTTPError:
    message = email.message.Message()
    for key, value in (headers or {}).items():
        message[key] = value
    return urllib.error.HTTPError(url, code, "error", message, io.BytesIO(b'{"error":"invalid_client"}'))


def _fake_open(monkeypatch: pytest.MonkeyPatch, responses: list[Any]) -> list[Any]:
    seen: list[Any] = []

    def fake_open_public(request: Any, *, timeout: float, label: str) -> _FakeResponse:
        seen.append(request)
        item = responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return _FakeResponse(json.dumps(item).encode())

    monkeypatch.setattr(netguard, "open_public", fake_open_public)
    return seen


def test_exchanges_form_encoded_credentials_and_caches_until_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _fake_open(
        monkeypatch,
        [{"access_token": "tok-1", "expires_in": 1200}, {"access_token": "tok-2", "expires_in": 1200}],
    )
    now = [1000.0]
    source = ClientCredentialsToken(
        TOKEN_URL,
        form={"grant_type": "client_credentials", "client_id": "cid", "client_secret": "s3cret"},
        label="example",
        clock=lambda: now[0],
    )

    assert source.bearer() == "tok-1"
    assert source.bearer() == "tok-1"
    assert len(seen) == 1
    request = seen[0]
    assert request.get_method() == "POST"
    assert request.full_url == TOKEN_URL
    assert request.get_header("Content-type") == "application/x-www-form-urlencoded"
    assert urllib.parse.parse_qs(request.data.decode()) == {
        "grant_type": ["client_credentials"],
        "client_id": ["cid"],
        "client_secret": ["s3cret"],
    }

    # Refreshes inside the skew window before the token actually expires.
    now[0] += 1200 - 30
    assert source.bearer() == "tok-2"
    assert len(seen) == 2


def test_invalidate_forces_a_new_exchange(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _fake_open(monkeypatch, [{"access_token": "a", "expires_in": 3600}, {"access_token": "b"}])
    source = ClientCredentialsToken(TOKEN_URL, form={"client_id": "c", "client_secret": "s"}, label="x")

    assert source.bearer() == "a"
    source.invalidate()
    assert source.bearer() == "b"
    assert len(seen) == 2


@pytest.mark.parametrize("code", [400, 401, 403])
def test_rejected_credentials_fail_closed_without_leaking_the_secret(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    _fake_open(monkeypatch, [_http_error(TOKEN_URL, code)])
    source = ClientCredentialsToken(
        TOKEN_URL, form={"client_id": "c", "client_secret": "very-secret"}, label="Jamf Pro"
    )

    with pytest.raises(CredentialRejectedError) as excinfo:
        source.bearer()
    assert "Jamf Pro" in str(excinfo.value)
    assert str(code) in str(excinfo.value)
    assert "very-secret" not in str(excinfo.value)


def test_missing_access_token_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_open(monkeypatch, [{"token_type": "bearer"}])
    source = ClientCredentialsToken(TOKEN_URL, form={"client_id": "c", "client_secret": "s"}, label="x")

    with pytest.raises(CredentialRejectedError, match="access_token"):
        source.bearer()


def test_token_exchange_retries_rate_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr("time.sleep", sleeps.append)
    _fake_open(
        monkeypatch,
        [_http_error(TOKEN_URL, 429, {"Retry-After": "2"}), {"access_token": "ok", "expires_in": 60}],
    )
    source = ClientCredentialsToken(TOKEN_URL, form={"client_id": "c", "client_secret": "s"}, label="x")

    assert source.bearer() == "ok"
    assert sleeps == [2.0]


def test_call_with_bearer_refreshes_once_on_401(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_open(monkeypatch, [{"access_token": "stale", "expires_in": 3600}, {"access_token": "fresh"}])
    source = ClientCredentialsToken(TOKEN_URL, form={"client_id": "c", "client_secret": "s"}, label="x")
    tokens: list[str] = []

    def call(token: str) -> str:
        tokens.append(token)
        if token == "stale":
            raise _http_error("https://api.example.com/data", 401)
        return "payload"

    assert source.call_with_bearer(call) == "payload"
    assert tokens == ["stale", "fresh"]


def test_call_with_bearer_fails_closed_after_second_401(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_open(monkeypatch, [{"access_token": "one"}, {"access_token": "two"}])
    source = ClientCredentialsToken(TOKEN_URL, form={"client_id": "c", "client_secret": "s"}, label="x")

    def call(_token: str) -> str:
        raise _http_error("https://api.example.com/data", 401)

    with pytest.raises(urllib.error.HTTPError):
        source.call_with_bearer(call)


def test_token_url_must_be_https() -> None:
    with pytest.raises(ValueError, match="https"):
        ClientCredentialsToken("http://idp.example.com/token", form={}, label="x")
