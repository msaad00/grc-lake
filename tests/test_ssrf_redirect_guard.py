"""Regression tests for the shared guarded-opener SSRF defense.

Validating only the first URL is not enough: urllib silently follows 3xx
redirects, and paginating clients follow server-supplied ``Link`` URLs. Both let
a validated host pivot a credentialed request at an internal address after the
boundary check passed. These tests pin the fix in ``netguard.open_guarded`` and
its use on every credentialed egress path (workflow actions + connector clients).
"""

from __future__ import annotations

import email.message
import urllib.request
from pathlib import Path

import pytest

import security_lakehouse.workflows as wf
from security_lakehouse import netguard
from security_lakehouse.connectors_google_workspace import GoogleWorkspaceClient
from security_lakehouse.connectors_okta import OktaClient
from security_lakehouse.connectors_siem import probe_siem_access


class _FakeResp:
    def __init__(self, body: bytes, link: str = "") -> None:
        self._body = body
        self.headers = email.message.Message()
        if link:
            self.headers["Link"] = link

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self, _amt: int | None = None) -> bytes:
        return self._body


def _private_dns(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, str]) -> None:
    """Resolve each host to a chosen IP so the SSRF check is deterministic."""

    def _getaddrinfo(host, port, *args, **kwargs):  # noqa: ANN001, ARG001
        ip = mapping[host]
        family = 10 if ":" in ip else 2
        return [(family, 1, 6, "", (ip, 0))]

    monkeypatch.setattr(netguard.socket, "getaddrinfo", _getaddrinfo)


# --- shared redirect handler ----------------------------------------------------


def _redirect(handler: netguard._GuardedRedirectHandler, req: urllib.request.Request, newurl: str):
    return handler.redirect_request(req, None, 302, "Found", email.message.Message(), newurl)


def test_guarded_redirect_revalidates_hop_target() -> None:
    seen: list[str] = []
    handler = netguard._GuardedRedirectHandler(seen.append)
    req = urllib.request.Request("https://ok.example/a")
    _redirect(handler, req, "https://ok.example/b")
    assert seen == ["https://ok.example/b"]


def test_guarded_redirect_raises_when_validator_rejects() -> None:
    def _deny(_url: str) -> None:
        raise ValueError("SSRF blocked")

    handler = netguard._GuardedRedirectHandler(_deny)
    req = urllib.request.Request("https://ok.example/a")
    with pytest.raises(ValueError, match="SSRF blocked"):
        _redirect(handler, req, "http://169.254.169.254/latest/meta-data/")


def test_guarded_redirect_strips_credentials_across_origin() -> None:
    handler = netguard._GuardedRedirectHandler(lambda _u: None)
    req = urllib.request.Request(
        "https://a.example/x",
        headers={"Authorization": "Bearer secret", "Cookie": "sid=1"},
    )
    hop = _redirect(handler, req, "https://b.example/y")
    assert hop.get_header("Authorization") is None
    assert hop.get_header("Cookie") is None


def test_guarded_redirect_keeps_credentials_same_origin() -> None:
    handler = netguard._GuardedRedirectHandler(lambda _u: None)
    req = urllib.request.Request(
        "https://a.example/x",
        headers={"Authorization": "Bearer secret"},
    )
    hop = _redirect(handler, req, "https://a.example/y")
    assert hop.get_header("Authorization") == "Bearer secret"


def test_open_public_rejects_private_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    _private_dns(monkeypatch, {"internal.example": "10.0.0.5"})
    with pytest.raises(ValueError, match="SSRF blocked"):
        netguard.open_public(urllib.request.Request("http://internal.example/x"), timeout=1)


# --- finding #3: Okta Link-header pivot -----------------------------------------


def test_okta_link_pivot_to_internal_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """A malicious org's Link: rel="next" cannot pivot the SSWS token internally."""
    _private_dns(monkeypatch, {"org.okta.com": "93.184.216.34", "evil.internal": "169.254.169.254"})

    # Page 1 (from the allowlisted public org) points rel="next" at an internal host.
    page1 = _FakeResp(b"[]", link='<http://evil.internal/latest/meta-data/>; rel="next"')

    class _Opener:
        def open(self, request, timeout=None):  # noqa: ANN001, ANN201, ARG002
            # Only ever reached for the first (public) page; the pivot is rejected
            # by open_guarded's validator before any opener call.
            return page1

    monkeypatch.setattr(netguard, "guarded_opener", lambda _validate, **_kw: _Opener())

    with pytest.raises(ValueError, match="SSRF blocked"):
        OktaClient("https://org.okta.com", token="00ADMIN-SSWS").users()


# --- finding #2: workflow redirect re-checks the egress allowlist ---------------


def test_workflow_redirect_target_rechecks_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    """_http_post's redirect validator is the egress allowlist + SSRF guard."""
    monkeypatch.setenv("TRUSTOPS_WORKFLOW_EGRESS_ALLOWLIST", "hooks.example.com")
    _private_dns(monkeypatch, {"hooks.example.com": "93.184.216.34"})

    handler = netguard._GuardedRedirectHandler(lambda u: wf._assert_egress_allowed(u, what="webhook"))
    req = urllib.request.Request("https://hooks.example.com/x")
    # A 302 to any non-allowlisted host is refused before the request is re-sent.
    with pytest.raises(ValueError, match="not in the egress allowlist"):
        _redirect(handler, req, "https://evil.example.org/x")


# --- finding #1: connector probe path runs the SSRF guard -----------------------


def test_siem_probe_blocks_private_host(monkeypatch: pytest.MonkeyPatch) -> None:
    _private_dns(monkeypatch, {"internal.local": "169.254.169.254"})
    result = probe_siem_access(
        credentials={"host": "http://internal.local", "token": "t"},
        options={"index": "alerts"},
    )
    assert result["ok"] is False


def test_google_workspace_client_routes_through_the_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fixed-host Google Workspace client is guarded too (no raw urlopen)."""
    _private_dns(monkeypatch, {"admin.googleapis.com": "169.254.169.254"})
    with pytest.raises(ValueError, match="SSRF blocked"):
        GoogleWorkspaceClient("C00cust", access_token="t").users()


def test_siem_discover_blocks_private_host(monkeypatch: pytest.MonkeyPatch) -> None:
    from security_lakehouse.connectors_siem import discover_siem_scope

    _private_dns(monkeypatch, {"internal.local": "10.0.0.9"})
    result = discover_siem_scope(
        credentials={"host": "http://internal.local", "token": "t"},
        options={},
    )
    assert result["ok"] is False


def test_workflow_action_webhook_redirect_to_internal_blocked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """End-to-end: a real 302 from an allowlisted host to loopback is refused."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    reached = {"internal": False}

    class _Redirector(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{internal.server_address[1]}/x")
            self.end_headers()

        def log_message(self, *a):  # noqa: ANN002, ANN202
            pass

    class _Internal(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            reached["internal"] = True
            self.send_response(200)
            self.end_headers()

        def do_GET(self):  # noqa: N802
            self.do_POST()

        def log_message(self, *a):  # noqa: ANN002, ANN202
            pass

    allow = HTTPServer(("127.0.0.1", 0), _Redirector)
    internal = HTTPServer(("127.0.0.1", 0), _Internal)
    threading.Thread(target=allow.serve_forever, daemon=True).start()
    threading.Thread(target=internal.serve_forever, daemon=True).start()

    allow_port = allow.server_address[1]
    monkeypatch.setenv("TRUSTOPS_WORKFLOW_EGRESS_ALLOWLIST", f"127.0.0.1:{allow_port}")
    # Treat the allowlisted loopback host as public so the initial request is sent;
    # the redirect target (a different loopback port) is NOT allowlisted.
    monkeypatch.setattr(netguard, "assert_resolved_ip_is_public", lambda host, **k: [host])
    monkeypatch.setattr(wf, "_webhook_backoff_sleep", lambda _s: None)

    with pytest.raises(ValueError, match="not in the egress allowlist"):
        wf.run_action(
            tmp_path,
            node_type="action.webhook",
            params={"url": f"http://127.0.0.1:{allow_port}/hook", "max_retries": 0},
        )
    assert reached["internal"] is False
