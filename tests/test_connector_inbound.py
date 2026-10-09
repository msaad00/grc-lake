"""Inbound connector robustness: SSRF guard + cursor/startAt pagination."""

from __future__ import annotations

import json

import pytest

from security_lakehouse import netguard
from security_lakehouse.connectors_jira import JiraClient
from security_lakehouse.connectors_okta import OktaClient, _next_link
from security_lakehouse.ingestion.paginate import next_link_url


class _FakeResp:
    def __init__(self, body: object, headers: dict[str, str] | None = None) -> None:
        self._body = json.dumps(body).encode("utf-8")
        self.headers = headers or {}

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *_: object) -> bool:
        return False


# --- netguard ---------------------------------------------------------------


def test_netguard_rejects_non_http_scheme() -> None:
    with pytest.raises(ValueError, match="scheme must be http"):
        netguard.assert_url_is_public("ftp://example.com/x", label="x")


def test_netguard_blocks_loopback() -> None:
    with pytest.raises(ValueError, match="SSRF blocked"):
        netguard.assert_url_is_public("http://127.0.0.1/api", label="x")


def test_netguard_blocks_private_range() -> None:
    with pytest.raises(ValueError, match="SSRF blocked"):
        netguard.assert_resolved_ip_is_public("10.0.0.5", label="x")


def test_netguard_allows_public_ip() -> None:
    assert netguard.assert_resolved_ip_is_public("8.8.8.8", label="x") == ["8.8.8.8"]


# --- Okta Link pagination ---------------------------------------------------


def test_next_link_parses_rel_next() -> None:
    header = '<https://org.okta.com/api/v1/users?after=abc&limit=200>; rel="next", <...>; rel="self"'
    assert _next_link(header) == "https://org.okta.com/api/v1/users?after=abc&limit=200"
    assert _next_link('<...>; rel="self"') is None


def test_shared_next_link_url_is_the_one_okta_uses() -> None:
    header = '<https://h.example/a?x=1>; rel="prev", <https://h.example/a?cursor=2>; rel="next"'
    assert next_link_url(header) == "https://h.example/a?cursor=2"
    assert next_link_url("") is None
    assert _next_link is next_link_url


def test_okta_users_follows_link_to_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = [
        _FakeResp([{"id": "u1"}, {"id": "u2"}], {"Link": '<https://org.okta.com/next>; rel="next"'}),
        _FakeResp([{"id": "u3"}], {"Link": '<...>; rel="self"'}),
    ]
    calls = {"n": 0}

    def fake_urlopen(_request, timeout=0, **_kwargs):
        resp = pages[calls["n"]]
        calls["n"] += 1
        return resp

    monkeypatch.setattr("security_lakehouse.netguard.open_public", fake_urlopen)
    client = OktaClient("https://org.okta.com", token="t")
    users = client.users()
    assert [u["id"] for u in users] == ["u1", "u2", "u3"]
    assert calls["n"] == 2


# --- Jira startAt pagination ------------------------------------------------


def test_jira_issues_follows_start_at_to_total(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = [
        _FakeResp({"issues": [{"key": "A-1"}, {"key": "A-2"}], "total": 3}),
        _FakeResp({"issues": [{"key": "A-3"}], "total": 3}),
    ]
    calls = {"n": 0}

    def fake_urlopen(_request, timeout=0, **_kwargs):
        resp = pages[calls["n"]]
        calls["n"] += 1
        return resp

    monkeypatch.setattr("security_lakehouse.netguard.open_public", fake_urlopen)
    client = JiraClient("https://acme.atlassian.net", email="e@x.com", token="t")
    issues = client.issues()
    assert [i["key"] for i in issues] == ["A-1", "A-2", "A-3"]
    assert calls["n"] == 2
