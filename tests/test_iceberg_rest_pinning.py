"""The tenant-facing Iceberg REST catalog connects to the address netguard validated."""

from __future__ import annotations

import socket
import threading

import pytest

pytest.importorskip("pyiceberg")

from security_lakehouse import iceberg_export, netguard

HOST = "rebind.evil.test"


def test_rest_catalog_cannot_be_rebound_to_an_internal_address(monkeypatch: pytest.MonkeyPatch) -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    listener.settimeout(0.2)
    port = listener.getsockname()[1]
    accepted: list[bytes] = []
    stop = threading.Event()

    def accept() -> None:
        while not stop.is_set():
            try:
                conn, _addr = listener.accept()
            except OSError:
                continue
            accepted.append(b"conn")
            conn.close()

    threading.Thread(target=accept, daemon=True).start()

    real = socket.getaddrinfo
    answers = {"n": 0}

    def rebinding(host, port_, *args, **kwargs):
        if host == HOST:
            answers["n"] += 1
            ip = "93.184.216.34" if answers["n"] == 1 else "127.0.0.1"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port_ or 0))]
        return real(host, port_, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", rebinding)
    monkeypatch.setenv("TRUSTOPS_TEST_REBIND_TOKEN", "tok")
    uri = f"https://{HOST}:{port}"
    netguard.assert_url_is_public(uri, label="iceberg rest catalog")
    try:
        with pytest.raises(iceberg_export.IcebergPublicationError):
            iceberg_export.rest_catalog(
                uri, warehouse="s3://bucket/wh", token_env="TRUSTOPS_TEST_REBIND_TOKEN", pin_public=True
            )
    finally:
        stop.set()
        listener.close()
    assert accepted == []
    assert answers["n"] >= 2


def test_pinned_adapter_connects_to_the_validated_address_and_keeps_the_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import http.server

    import requests

    seen: list[str | None] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Host"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    validated: list[str] = []

    def fake_validate(host: str, *, label: str = "target") -> list[str]:
        validated.append(host)
        return ["127.0.0.1"]

    monkeypatch.setattr(netguard, "assert_resolved_ip_is_public", fake_validate)
    session = requests.Session()
    session.trust_env = False
    session.mount("http://", netguard.pinned_requests_adapter(label="t"))
    try:
        resp = session.get(f"http://catalog.example:{server.server_address[1]}/v1/config", timeout=5)
    finally:
        server.shutdown()
    assert resp.status_code == 200
    assert validated == ["catalog.example"]
    assert seen == [f"catalog.example:{server.server_address[1]}"]
