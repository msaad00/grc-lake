"""Remote MCP must not forward credentials on redirects or accept broken envelopes."""

import io
import json
import urllib.error

import pytest

from security_lakehouse import mcp_server, netguard


@pytest.fixture
def remote(monkeypatch):
    monkeypatch.setenv("GRC_LAKE_MCP_MODE", "remote")
    monkeypatch.setenv("GRC_LAKE_API_URL", "https://api.example.test")
    monkeypatch.setenv("GRC_LAKE_API_KEY", "fixture-private-token")
    monkeypatch.delenv("GRC_LAKE_API_ALLOW_PRIVATE", raising=False)
    monkeypatch.setattr(netguard, "assert_url_is_public", lambda *a, **kw: "api.example.test")


@pytest.mark.parametrize(
    "payload",
    [
        b'{"data": NaN,"meta":{},"errors":[]}',
        b'{"data":{},"data":[],"meta":{},"errors":[]}',
        b'{"data":{}}',
        b'{"data":{},"meta":{},"errors":[{"code":"denied"}]}',
        b"[]",
        b"\xff",
    ],
)
def test_invalid_success_response_rejected(remote, monkeypatch, payload):
    monkeypatch.setattr(mcp_server, "_open_api_request", lambda *a, **kw: io.BytesIO(payload))
    with pytest.raises(ValueError, match="invalid (JSON response|response shape)"):
        mcp_server._server_api_request("GET", "/api/v1/controls")


def test_response_read_has_a_hard_byte_bound(remote, monkeypatch):
    monkeypatch.setattr(mcp_server, "MAX_API_RESPONSE_BYTES", 64)

    class Response(io.BytesIO):
        def read(self, size=-1):
            assert size == 65
            return super().read(size)

    monkeypatch.setattr(mcp_server, "_open_api_request", lambda *a, **kw: Response(b"x" * 200))
    with pytest.raises(ValueError, match="smaller page"):
        mcp_server._server_api_request("GET", "/api/v1/controls")


def test_error_cannot_echo_bearer_token(remote, monkeypatch):
    def fail(*a, **kw):
        raise urllib.error.HTTPError(
            "https://api.example.test",
            403,
            "Forbidden",
            {},
            io.BytesIO(json.dumps({"errors": [{"detail": "fixture-private-token forbidden"}]}).encode()),
        )

    monkeypatch.setattr(mcp_server, "_open_api_request", fail)
    with pytest.raises(ValueError, match="403") as caught:
        mcp_server._server_api_request("GET", "/api/v1/controls")
    assert "fixture-private-token" not in str(caught.value)


def test_public_transport_uses_guarded_connections_and_refuses_redirects(remote, monkeypatch):
    def guarded(request, *, timeout, validate, label):
        assert label == "GRC_LAKE_API_URL"
        validate(request.full_url)
        validate("https://other.example.test/stolen-token")
        pytest.fail("redirect accepted")

    monkeypatch.setattr(netguard, "open_guarded", guarded)
    with pytest.raises(ValueError, match="redirects are not allowed"):
        mcp_server._server_api_request("GET", "/api/v1/controls")


@pytest.mark.parametrize(
    "url",
    [
        "https://user:password@example.test",
        "https://example.test/?token=hidden",
        "https://example.test/#fragment",
        "https://example.test?",
        "https://example.test#",
        "https://",
        "https://exam\nple.test",
    ],
)
def test_operator_url_rejects_ambiguous_or_credential_fields(remote, monkeypatch, url):
    monkeypatch.setenv("GRC_LAKE_API_URL", url)
    with pytest.raises(ValueError):
        mcp_server.resolve_api_base_url()


@pytest.mark.parametrize("timeout", ["nan", "inf", "-inf"])
def test_nonfinite_timeouts_fail_before_network(remote, monkeypatch, timeout):
    monkeypatch.setenv("GRC_LAKE_API_TIMEOUT_SECONDS", timeout)
    monkeypatch.setattr(mcp_server, "_open_api_request", lambda *a, **kw: pytest.fail("invalid timeout connected"))
    with pytest.raises(ValueError, match="finite"):
        mcp_server._server_api_request("GET", "/api/v1/controls")


def test_explicit_local_mode_disables_server_only_tools(remote, monkeypatch):
    monkeypatch.setenv("GRC_LAKE_MCP_MODE", "local")
    monkeypatch.setattr(mcp_server, "_open_api_request", lambda *a, **kw: pytest.fail("local mode connected"))
    with pytest.raises(ValueError, match="requires remote"):
        mcp_server._server_api_request("GET", "/api/v1/agent-runs")


def test_private_http_redirect_never_reaches_second_origin(monkeypatch):
    pytest.importorskip("uvicorn")
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.responses import RedirectResponse

    from test_async_sdk import _server

    target = FastAPI()
    received = []

    @target.get("/capture")
    def capture():
        received.append(True)
        return {"data": {}, "meta": {}, "errors": []}

    with _server(target) as target_url:
        source = FastAPI()

        @source.get("/api/v1/controls")
        def redirect():
            return RedirectResponse(target_url + "/capture")

        with _server(source) as source_url:
            monkeypatch.setenv("GRC_LAKE_API_URL", source_url)
            monkeypatch.setenv("GRC_LAKE_API_KEY", "fixture-token")
            monkeypatch.setenv("GRC_LAKE_MCP_MODE", "remote")
            monkeypatch.setenv("GRC_LAKE_API_ALLOW_PRIVATE", "1")
            with pytest.raises(ValueError, match="redirects are not allowed"):
                mcp_server._server_api_request("GET", "/api/v1/controls")
    assert received == []
