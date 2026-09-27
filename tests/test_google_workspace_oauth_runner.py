"""Runner wiring for Google Workspace OAuth refresh (file-first secrets).

The connector runner builds a self-refreshing token source when refresh
material is configured, resolving the refresh token and client secret
file-first (a ``*_FILE`` path is preferred over an inline env var so the raw
secret lives on disk with least-privilege permissions and can be revoked by
rotating the file). The resolved access token is never persisted.
"""

from __future__ import annotations

import email.message
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from security_lakehouse import netguard
from security_lakehouse.connector_runner import (
    DEFAULT_TOKEN_ENV,
    _collect_google_workspace,
    _read_secret_file_first,
    _resolve_provider_secret,
)
from security_lakehouse.connectors_google_workspace import GOOGLE_TOKEN_URI


class _Resp:
    def __init__(self, body: dict[str, object]) -> None:
        self._body = json.dumps(body).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False


class _FakeDirectory:
    """Serves the token endpoint + directory reads, minting one fresh token."""

    def __init__(self, *, mint: str = "fresh") -> None:
        self.mint = mint
        self.valid_token: str | None = None
        self.refresh_calls = 0
        self.last_refresh_token: str | None = None

    def __call__(self, request: urllib.request.Request, timeout: float | None = None, **_kw: object) -> _Resp:
        url = request.full_url
        if url.startswith(GOOGLE_TOKEN_URI):
            self.refresh_calls += 1
            params = dict(urllib.parse.parse_qsl((request.data or b"").decode("ascii")))
            self.last_refresh_token = params.get("refresh_token")
            self.valid_token = self.mint
            return _Resp({"access_token": self.mint, "expires_in": 3600})
        auth = request.get_header("Authorization") or ""
        if auth.split(" ", 1)[-1] != self.valid_token:
            raise urllib.error.HTTPError(url, 401, "err", email.message.Message(), None)
        if "/users" in url:
            return _Resp({"users": [{"id": "u1", "primaryEmail": "u1@acme.test", "isEnrolledIn2Sv": True}]})
        return _Resp({"groups": []})


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "sleep", lambda _s: None)


def test_read_secret_file_first_prefers_mounted_file(tmp_path: Path) -> None:
    secret = tmp_path / "refresh.txt"
    secret.write_text("from-file\n", encoding="utf-8")
    env = {"REF": "from-env", "REF_FILE": str(secret)}
    # The *_FILE mount wins over the inline value, and trailing whitespace is trimmed.
    assert _read_secret_file_first("REF", env) == "from-file"
    # No file configured -> falls back to the inline env value.
    assert _read_secret_file_first("REF", {"REF": "from-env"}) == "from-env"
    # Nothing configured -> None.
    assert _read_secret_file_first("REF", {}) is None


def test_read_secret_file_first_missing_file_fails_closed(tmp_path: Path) -> None:
    env = {"REF": "inline", "REF_FILE": str(tmp_path / "does-not-exist")}
    # A configured-but-unreadable secret file fails closed rather than silently
    # falling back to the inline env value.
    assert _read_secret_file_first("REF", env) is None


def test_unreadable_secret_file_logs_a_warning_naming_the_variable(tmp_path: Path, caplog) -> None:
    import logging

    missing = tmp_path / "does-not-exist"
    with caplog.at_level(logging.WARNING, logger="security_lakehouse.connector_runner"):
        assert _read_secret_file_first("REF", {"REF": "inline-secret", "REF_FILE": str(missing)}) is None
    messages = [record.getMessage() for record in caplog.records]
    assert any("REF_FILE" in message for message in messages)
    assert not any("inline-secret" in message for message in messages)


def test_resolve_provider_secret_prefers_explicit_ref(tmp_path: Path) -> None:
    ref_file = tmp_path / "explicit"
    ref_file.write_text("explicit-secret", encoding="utf-8")
    env = {"CUSTOM_REF_FILE": str(ref_file), "PROVIDER_DEFAULT": "default-secret"}
    assert _resolve_provider_secret("CUSTOM_REF", "PROVIDER_DEFAULT", env) == "explicit-secret"
    # Empty ref -> provider default is used.
    assert _resolve_provider_secret("", "PROVIDER_DEFAULT", env) == "default-secret"


def test_collect_google_workspace_refreshes_with_file_first_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = tmp_path / "refresh.txt"
    secret.write_text("rt-from-file\n", encoding="utf-8")
    env = {
        "GOOGLE_WORKSPACE_REFRESH_TOKEN_FILE": str(secret),
        "GOOGLE_WORKSPACE_OAUTH_CLIENT_ID": "cid",
        "GOOGLE_WORKSPACE_OAUTH_CLIENT_SECRET": "csecret",
    }
    fake = _FakeDirectory(mint="fresh")
    monkeypatch.setattr(netguard, "open_public", fake)

    rows = _collect_google_workspace(
        fixture_dir=None,
        token_env=DEFAULT_TOKEN_ENV,
        env=env,
        credentials={"customer_id": "C00acme"},
    )

    # Evidence collected without any pre-supplied access token: the source
    # minted one from the refresh token on first use (proactive refresh).
    assert rows
    assert all(r["source"] == "google_workspace" for r in rows)
    assert fake.refresh_calls == 1
    assert fake.last_refresh_token == "rt-from-file"  # came from the *_FILE mount


def test_collect_google_workspace_static_token_path_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    # With no refresh material, the connector uses the static token unchanged and
    # never contacts the token endpoint.
    fake = _FakeDirectory(mint="unused")
    fake.valid_token = "static"
    monkeypatch.setattr(netguard, "open_public", fake)

    rows = _collect_google_workspace(
        fixture_dir=None,
        token_env=DEFAULT_TOKEN_ENV,
        env={"GOOGLE_WORKSPACE_ACCESS_TOKEN": "static"},
        credentials={"customer_id": "C00acme"},
    )
    assert rows
    assert fake.refresh_calls == 0
