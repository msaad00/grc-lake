"""HTTP connectors retry transient 429/5xx instead of failing collection.

Jira and Google Workspace previously issued a single ``urlopen`` with no retry,
so one rate-limit response failed the whole sync. They now share the same
``ingestion.backoff`` retry path as Okta. These tests inject a flaky transport
(429 a few times, then success) and assert the connector recovers, and that a
non-retryable status (404) still raises immediately.
"""

from __future__ import annotations

import email.message
import json
import time
import urllib.error
import urllib.request

import pytest

from security_lakehouse import netguard
from security_lakehouse.connectors_google_workspace import GoogleWorkspaceClient
from security_lakehouse.connectors_jira import JiraClient
from security_lakehouse.ingestion import backoff


class _Resp:
    def __init__(self, body: str) -> None:
        self._body = body.encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False

    @property
    def headers(self) -> email.message.Message:
        return email.message.Message()


def _http_error(code: int, *, retry_after: int | None = None) -> urllib.error.HTTPError:
    hdrs = email.message.Message()
    if retry_after is not None:
        hdrs["Retry-After"] = str(retry_after)
    return urllib.error.HTTPError("http://example", code, "err", hdrs, None)


def _flaky_opener(fail_times: int, code: int, body: str):
    calls = {"n": 0}

    def _open(_request, timeout=None, **_kwargs):
        n = calls["n"]
        calls["n"] += 1
        if n < fail_times:
            raise _http_error(code, retry_after=0)
        return _Resp(body)

    return _open, calls


# --- promoted shared helpers -------------------------------------------------


def test_is_retryable_http_classifies_status() -> None:
    assert backoff.is_retryable_http(_http_error(429)) is True
    assert backoff.is_retryable_http(_http_error(503)) is True
    assert backoff.is_retryable_http(_http_error(404)) is False
    assert backoff.is_retryable_http(ValueError("nope")) is False


def test_http_retry_after_reads_header() -> None:
    assert backoff.http_retry_after(_http_error(429, retry_after=7)) == 7.0
    assert backoff.http_retry_after(_http_error(429)) is None


# --- Jira --------------------------------------------------------------------


def test_jira_retries_then_succeeds_on_429(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    opener, calls = _flaky_opener(2, 429, json.dumps({"values": [], "isLast": True}))
    monkeypatch.setattr(netguard, "open_public", opener)
    client = JiraClient("https://acme.atlassian.net", email="a@b.c", token="t")
    out = client._json("https://acme.atlassian.net/rest/api/3/search")
    assert isinstance(out, dict)
    assert calls["n"] == 3  # two 429s then success


def test_jira_does_not_retry_on_404(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    opener, calls = _flaky_opener(1, 404, "{}")
    monkeypatch.setattr(netguard, "open_public", opener)
    client = JiraClient("https://acme.atlassian.net", email="a@b.c", token="t")
    with pytest.raises(urllib.error.HTTPError):
        client._json("https://acme.atlassian.net/rest/api/3/search")
    assert calls["n"] == 1  # no retry on a permanent error


# --- Google Workspace --------------------------------------------------------


def test_google_workspace_retries_then_succeeds_on_503(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    opener, calls = _flaky_opener(1, 503, json.dumps({"users": [{"id": "u1"}]}))
    monkeypatch.setattr(netguard, "open_public", opener)
    client = GoogleWorkspaceClient("C00acme", access_token="t")
    out = client._json_collection("https://admin.googleapis.com/users", key="users")
    assert out == [{"id": "u1"}]
    assert calls["n"] == 2  # one 503 then success
