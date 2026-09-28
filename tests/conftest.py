"""Shared pytest configuration."""

from __future__ import annotations

import json
import os

import pytest

# Signed session cookies are mandatory whenever server auth is enabled.
os.environ.setdefault("TRUSTOPS_COOKIE_SIGNING_KEY", "test-cookie-signing-key-for-pytest-only")


# Minimal Iceberg REST catalog on loopback for REST client hardening tests.
@pytest.fixture
def rest_stub():
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    state = {"headers": [], "overrides": {}, "redirect": False, "expired": False}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["headers"].append(self.headers.get("Authorization"))
            if state["redirect"]:
                self.send_response(302)
                self.send_header("Location", "/redirect-target")
                self.end_headers()
                return
            if state["expired"] and "/config" not in self.path:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":{"message":"expired","type":"UnauthorizedException","code":401}}')
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = (
                {"defaults": {}, "overrides": state["overrides"]} if "/config" in self.path else {"namespaces": []}
            )
            self.wfile.write(json.dumps(payload).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
