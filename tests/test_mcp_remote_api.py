"""Remote MCP API helper tests that do not require the optional MCP SDK."""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from security_lakehouse import mcp_server, netguard


def _no_ssrf_check(url: str, **_kw: object) -> str:
    """Bypass DNS resolution in unit tests that use non-resolving test domains."""
    return url.split("//", 1)[1].split("/")[0]


def test_resolve_api_base_url_requires_http(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TRUSTOPS_API_URL", raising=False)
    with pytest.raises(ValueError, match="TRUSTOPS_API_URL"):
        mcp_server.resolve_api_base_url()

    monkeypatch.setenv("TRUSTOPS_API_URL", "file:///tmp/lake")
    with pytest.raises(ValueError, match="http or https"):
        mcp_server.resolve_api_base_url()

    monkeypatch.setenv("TRUSTOPS_API_URL", "https://trustops.example.test/")
    monkeypatch.setattr(netguard, "assert_url_is_public", _no_ssrf_check)
    assert mcp_server.resolve_api_base_url() == "https://trustops.example.test"


def test_server_api_request_sends_bearer_json_without_secret_in_url(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _size: int = -1) -> bytes:
            return json.dumps({"data": {"ok": True}, "meta": {"resource": "agent-runs"}, "errors": []}).encode()

    def fake_urlopen(request: urllib.request.Request, *, timeout: float):
        captured["url"] = request.full_url
        captured["method"] = request.get_method()
        captured["authorization"] = request.get_header("Authorization")
        captured["content_type"] = request.get_header("Content-type")
        captured["body"] = request.data
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setenv("TRUSTOPS_API_URL", "https://trustops.example.test/")
    monkeypatch.setenv("TRUSTOPS_API_KEY", "secret-token")
    monkeypatch.setattr(mcp_server, "_open_api_request", fake_urlopen)
    monkeypatch.setattr(netguard, "assert_url_is_public", _no_ssrf_check)

    body = mcp_server._server_api_request("POST", "/api/v1/agent-runs", {"harness": "posture_review"}, limit=10)

    assert body["data"]["ok"] is True
    assert captured["url"] == "https://trustops.example.test/api/v1/agent-runs?limit=10"
    assert "secret-token" not in str(captured["url"])
    assert captured["method"] == "POST"
    assert captured["authorization"] == "Bearer secret-token"
    assert captured["content_type"] == "application/json"
    assert json.loads(captured["body"]) == {"harness": "posture_review"}
    assert captured["timeout"] == 30.0


def test_server_api_request_redacts_token_from_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(_request: urllib.request.Request, *, timeout: float):
        raise urllib.error.HTTPError(
            url="https://trustops.example.test/api/v1/agent-runs",
            code=403,
            msg="Forbidden",
            hdrs={},
            fp=io.BytesIO(b'{"errors":[{"detail":"forbidden"}]}'),
        )

    monkeypatch.setenv("TRUSTOPS_API_URL", "https://trustops.example.test")
    monkeypatch.setenv("TRUSTOPS_API_KEY", "secret-token")
    monkeypatch.setattr(mcp_server, "_open_api_request", fake_urlopen)
    monkeypatch.setattr(netguard, "assert_url_is_public", _no_ssrf_check)

    with pytest.raises(ValueError) as exc:
        mcp_server._server_api_request("GET", "/api/v1/agent-runs")

    message = str(exc.value)
    assert "forbidden" in message
    assert "secret-token" not in message


def test_get_lake_or_remote_uses_server_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    def fake_server(method: str, path: str, body=None, **params):
        calls.append((method, path))
        return {"data": {"inventory_count": 2}, "meta": {"resource": "platform.ai-governance"}, "errors": []}

    monkeypatch.setenv("TRUSTOPS_API_URL", "https://trustops.example.test")
    monkeypatch.setenv("TRUSTOPS_API_KEY", "secret-token")
    monkeypatch.setattr(mcp_server, "_server_api_request", fake_server)

    data = mcp_server._get_lake_or_remote("/api/v1/platform/ai-governance", Path("/tmp/lake"))
    assert data["inventory_count"] == 2
    assert calls == [("GET", "/api/v1/platform/ai-governance")]


def test_session_hash_is_keyed_not_bare_sha256() -> None:
    from security_lakehouse.auth.sessions import hash_session_token

    token = "tops_sess_" + "a" * 64
    digest = hash_session_token(token)
    assert len(digest) == 64
    assert digest != __import__("hashlib").sha256(token.encode()).hexdigest()
