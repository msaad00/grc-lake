"""Request guards on the unauthenticated local-mode server.

Local mode has no authentication by design, so the browser boundary is what
keeps another website (or a DNS-rebinding page) from driving it: the Host header
must name this machine, a cross-origin browser POST is refused, a body must be
JSON, and Content-Length is validated and capped.
"""

from __future__ import annotations

import http.client
import json
from http import HTTPStatus
from pathlib import Path

import pytest

from test_api_v1 import _spin


@pytest.fixture
def server(tmp_path: Path):
    srv = _spin(tmp_path)
    try:
        yield srv
    finally:
        srv.shutdown()


def _send(
    server,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    skip_host: bool = False,
) -> tuple[int, dict[str, object]]:
    host, port = server.server_address
    conn = http.client.HTTPConnection(host, port, timeout=30)
    try:
        conn.putrequest(method, path, skip_host=skip_host, skip_accept_encoding=True)
        merged = dict(headers or {})
        if body is not None and "Content-Length" not in merged:
            merged["Content-Length"] = str(len(body))
        for key, value in merged.items():
            conn.putheader(key, value)
        conn.endheaders()
        if body:
            conn.send(body)
        resp = conn.getresponse()
        raw = resp.read()
        return resp.status, json.loads(raw.decode("utf-8")) if raw else {}
    finally:
        conn.close()


def _origin(server) -> str:
    host, port = server.server_address
    return f"http://{host}:{port}"


JSON = {"Content-Type": "application/json"}


def test_same_origin_json_post_is_accepted(server) -> None:
    status, body = _send(
        server,
        "POST",
        "/api/v1/snapshots",
        body=json.dumps({"reason": "local"}).encode(),
        headers={**JSON, "Origin": _origin(server)},
    )
    assert status == HTTPStatus.CREATED, body


def test_non_browser_json_post_without_origin_is_accepted(server) -> None:
    status, _ = _send(server, "POST", "/api/v1/snapshots", body=b"{}", headers=JSON)
    assert status == HTTPStatus.CREATED


@pytest.mark.parametrize("origin", ["http://evil.example", "null", "http://127.0.0.1:1", "https://localhost.evil"])
def test_cross_origin_post_is_refused(server, origin: str) -> None:
    status, body = _send(
        server,
        "POST",
        "/api/v1/snapshots",
        body=b"{}",
        headers={**JSON, "Origin": origin},
    )
    assert status == HTTPStatus.FORBIDDEN
    assert body["errors"][0]["code"] == "forbidden"


def test_cross_origin_legacy_post_is_refused(server) -> None:
    status, body = _send(
        server,
        "POST",
        "/api/snapshots",
        body=b"{}",
        headers={**JSON, "Origin": "http://evil.example"},
    )
    assert status == HTTPStatus.FORBIDDEN
    assert body["error"] == "forbidden"


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data"])
def test_non_json_post_body_is_refused(server, content_type: str) -> None:
    status, body = _send(
        server,
        "POST",
        "/api/v1/snapshots",
        body=b'{"reason": "x"}',
        headers={"Content-Type": content_type},
    )
    assert status == HTTPStatus.UNSUPPORTED_MEDIA_TYPE
    assert body["errors"][0]["code"] == "unsupported_media_type"


def test_json_content_type_with_charset_is_accepted(server) -> None:
    status, _ = _send(
        server,
        "POST",
        "/api/v1/snapshots",
        body=b"{}",
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    assert status == HTTPStatus.CREATED


def test_non_numeric_content_length_is_a_bad_request(server) -> None:
    status, body = _send(
        server,
        "POST",
        "/api/v1/snapshots",
        body=b"{}",
        headers={**JSON, "Content-Length": "abc"},
    )
    assert status == HTTPStatus.BAD_REQUEST
    assert body["errors"][0]["code"] == "bad_request"


def test_oversized_content_length_is_refused_before_reading(server) -> None:
    status, body = _send(
        server,
        "POST",
        "/api/v1/snapshots",
        headers={**JSON, "Content-Length": str(50 * 1024 * 1024)},
    )
    assert status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    assert body["errors"][0]["code"] == "payload_too_large"


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_foreign_host_header_is_refused(server, method: str) -> None:
    """A DNS-rebinding page reaches 127.0.0.1 with its own hostname in Host."""
    _host, port = server.server_address
    status, _ = _send(
        server,
        method,
        "/api/v1/controls",
        body=b"{}" if method == "POST" else None,
        headers={**JSON, "Host": f"rebind.evil.example:{port}"},
        skip_host=True,
    )
    assert status == HTTPStatus.FORBIDDEN


@pytest.mark.parametrize("host_header", ["localhost", "127.0.0.1", "[::1]"])
def test_loopback_host_names_are_accepted(server, host_header: str) -> None:
    _host, port = server.server_address
    status, _ = _send(server, "GET", "/api/v1/controls", headers={"Host": f"{host_header}:{port}"}, skip_host=True)
    assert status == HTTPStatus.OK
