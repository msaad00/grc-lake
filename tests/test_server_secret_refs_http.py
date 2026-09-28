"""The hosted server applies the secret-ref policy on every tenant request path."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from security_lakehouse.execution_mode import COMMERCIAL_HOSTED_ENV, in_server_mode  # noqa: E402
from security_lakehouse.server_app import create_app  # noqa: E402
from test_api_v1 import _request, _seed_lake, _spin  # noqa: E402

CONFIGURE = "/api/v1/connectors/jamf-devices/configure"
LEGACY_CONFIGURE = "/api/connectors/jamf-devices/configure"


def _payload(ref: str) -> dict[str, object]:
    return {
        "state": "disabled",
        "credentials": {"base_url": "https://acme.jamfcloud.com", "client_id": "cid", "client_secret_ref": ref},
    }


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.delenv(COMMERCIAL_HOSTED_ENV, raising=False)
    _seed_lake(tmp_path)
    return TestClient(create_app(tmp_path, require_auth=False))


@pytest.mark.parametrize("ref", ["TRUSTOPS_COOKIE_SIGNING_KEY", "DATABASE_URL", "STRIPE_SECRET_KEY", "OKTA_API_TOKEN"])
def test_server_configure_refuses_refs_outside_policy(client: TestClient, ref: str) -> None:
    resp = client.post(CONFIGURE, json=_payload(ref))
    assert resp.status_code == HTTPStatus.BAD_REQUEST
    message = resp.json()["errors"][0]["detail"]
    assert "client_secret_ref" in message
    assert ref not in message


def test_server_legacy_configure_refuses_server_secret_ref(client: TestClient) -> None:
    resp = client.post(LEGACY_CONFIGURE, json=_payload("TRUSTOPS_COOKIE_SIGNING_KEY"))
    assert resp.status_code == HTTPStatus.BAD_REQUEST


def test_server_configure_accepts_the_tenant_prefix(client: TestClient) -> None:
    # Insecure (no-auth) mode serves the synthetic "insecure" tenant.
    resp = client.post(CONFIGURE, json=_payload("TRUSTOPS_TENANT_INSECURE_JAMF_SECRET"))
    assert resp.status_code == HTTPStatus.CREATED, resp.json()


def test_server_mode_does_not_leak_out_of_requests(client: TestClient) -> None:
    client.post(CONFIGURE, json=_payload("DATABASE_URL"))
    assert in_server_mode() is False


def test_local_stdlib_server_keeps_accepting_any_ref(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(COMMERCIAL_HOSTED_ENV, raising=False)
    _seed_lake(tmp_path)
    server = _spin(tmp_path)
    try:
        status, body = _request(server, "POST", CONFIGURE, _payload("TRUSTOPS_COOKIE_SIGNING_KEY"))
    finally:
        server.shutdown()
    assert status == HTTPStatus.CREATED, body
