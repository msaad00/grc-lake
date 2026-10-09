"""Hosted cloud linking collects tenant-delegated credentials, never server identity.

In server mode the Azure link must name the tenant's own Entra app registration
and the GCP link a service account to impersonate; both are validated at link
time with the same rules the readers enforce. The Azure admin-consent callback
is unauthenticated, so the Entra tenant it reports is never written into a
connector config.
"""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

from security_lakehouse.cloud_linking import (
    complete_cloud_link,
    record_azure_consent,
    start_cloud_link,
)
from security_lakehouse.execution_mode import COMMERCIAL_HOSTED_ENV, server_execution
from security_lakehouse.secret_refs import tenant_secret_prefix

TENANT = "3f2b8c1e-9a4d-4c2b-8f1e-2a6b7c8d9e0f"
PREFIX = "GRC_LAKE_TENANT_3F2B8C1E_9A4D_4C2B_8F1E_2A6B7C8D9E0F__"
SUBSCRIPTION = "11111111-2222-3333-4444-555555555555"
CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
ENTRA_TENANT = "99999999-8888-7777-6666-555555555555"
SERVICE_ACCOUNT = "trustops-reader@customer-proj.iam.gserviceaccount.com"


@pytest.fixture(autouse=True)
def _no_hosted_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(COMMERCIAL_HOSTED_ENV, raising=False)
    monkeypatch.delenv("GRC_LAKE_CONNECTOR_SECRET_REFS", raising=False)


def _azure_app(**overrides: str) -> dict[str, str]:
    return {
        "tenant_id": ENTRA_TENANT,
        "client_id": CLIENT_ID,
        "client_secret_ref": f"{PREFIX}AZURE_CLIENT_SECRET",
        **overrides,
    }


# --- session capability ------------------------------------------------------


def test_prefix_constant_matches_the_secret_ref_policy() -> None:
    assert tenant_secret_prefix(TENANT) == PREFIX


def test_hosted_session_reports_delegation_and_offers_no_server_consent_app(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GRC_LAKE_AZURE_LINK_CLIENT_ID", "server-multitenant-app")
    monkeypatch.setenv("GRC_LAKE_PUBLIC_URL", "https://demo.example.com")
    with server_execution(TENANT):
        session = start_cloud_link(tmp_path, "azure-posture", tenant_id="spoofed-by-body")

    assert session["delegation"] == {"required": True, "secret_ref_prefix": PREFIX}
    # The server never collects with its own Azure identity, so it must not
    # hand out consent for a server-owned multi-tenant app.
    assert session["consent_url"] is None
    assert session["azure_app_id"] is None
    assert session["tenant_id"] == TENANT


def test_local_session_reports_no_delegation_requirement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRC_LAKE_AZURE_LINK_CLIENT_ID", "azure-client-id")
    monkeypatch.setenv("GRC_LAKE_PUBLIC_URL", "https://demo.example.com")
    session = start_cloud_link(tmp_path, "azure-posture", tenant_id="tenant-a")

    assert session["delegation"] == {"required": False, "secret_ref_prefix": None}
    assert session["consent_url"]


# --- Azure -------------------------------------------------------------------


def _complete_azure(tmp_path: Path, delegation: dict[str, str] | None) -> dict:
    session = start_cloud_link(tmp_path, "azure-posture", tenant_id="tenant-a")
    return complete_cloud_link(
        tmp_path,
        "azure-posture",
        session_id=session["session_id"],
        actor="test",
        subscription_id=SUBSCRIPTION,
        delegation=delegation,
    )


def test_hosted_azure_link_stages_the_tenant_app_registration(tmp_path: Path) -> None:
    with server_execution(TENANT):
        result = _complete_azure(tmp_path, _azure_app())

    credentials = result["configure"]["credentials"]
    assert credentials == {
        "subscription_id": SUBSCRIPTION,
        "tenant_id": ENTRA_TENANT,
        "client_id": CLIENT_ID,
        "client_secret_ref": f"{PREFIX}AZURE_CLIENT_SECRET",
    }


@pytest.mark.parametrize(
    ("delegation", "message"),
    [
        (None, "requires tenant_id, client_id"),
        ({}, "requires tenant_id, client_id"),
        (_azure_app(client_id="not-a-guid"), "client_id"),
        (_azure_app(tenant_id="bad tenant!"), "tenant_id"),
        (_azure_app(client_certificate_ref=f"{PREFIX}AZURE_CERT"), "exactly one"),
        (_azure_app(client_secret_ref=""), "exactly one"),
        (_azure_app(client_secret_ref="AZURE_CLIENT_SECRET"), PREFIX),
        (_azure_app(client_secret_ref="GRC_LAKE_TENANT_OTHER__AZURE_CLIENT_SECRET"), PREFIX),
        (_azure_app(client_secret_ref="s3cr3t value=="), "must name an environment variable"),
        (_azure_app(unexpected="x"), "unexpected"),
    ],
)
def test_hosted_azure_link_refuses_incomplete_or_unsafe_delegation(
    tmp_path: Path, delegation: dict[str, str] | None, message: str
) -> None:
    with server_execution(TENANT), pytest.raises(ValueError, match=message):
        _complete_azure(tmp_path, delegation)


def test_local_azure_link_keeps_the_ambient_identity_path(tmp_path: Path) -> None:
    result = _complete_azure(tmp_path, None)
    assert result["configure"]["credentials"] == {"subscription_id": SUBSCRIPTION}


def test_local_azure_link_still_validates_a_supplied_app_registration(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must name an environment variable"):
        _complete_azure(tmp_path, _azure_app(client_secret_ref="raw secret value"))
    result = _complete_azure(tmp_path, _azure_app(client_secret_ref="AZURE_CLIENT_SECRET"))
    assert result["configure"]["credentials"]["client_secret_ref"] == "AZURE_CLIENT_SECRET"


@pytest.mark.parametrize("hosted", [False, True])
def test_consent_callback_tenant_is_never_written_to_connector_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hosted: bool
) -> None:
    monkeypatch.setenv("GRC_LAKE_AZURE_LINK_CLIENT_ID", "azure-client-id")
    session = start_cloud_link(tmp_path, "azure-posture", tenant_id="tenant-a")
    # Anyone holding the state value can call the unauthenticated callback
    # with any tenant; that value must not flow into the collector config.
    record_azure_consent(
        tmp_path,
        session_id=session["session_id"],
        azure_tenant_id="attacker-chosen-tenant",
        admin_consent=True,
    )
    delegation = _azure_app() if hosted else None
    if hosted:
        with server_execution(TENANT):
            result = complete_cloud_link(
                tmp_path,
                "azure-posture",
                session_id=session["session_id"],
                actor="test",
                subscription_id=SUBSCRIPTION,
                delegation=delegation,
            )
    else:
        result = complete_cloud_link(
            tmp_path,
            "azure-posture",
            session_id=session["session_id"],
            actor="test",
            subscription_id=SUBSCRIPTION,
        )
    configure = result["configure"]
    assert "attacker-chosen-tenant" not in repr(configure)
    assert "azure_tenant_id" not in (configure.get("options") or {})


# --- GCP ---------------------------------------------------------------------


def _complete_gcp(tmp_path: Path, delegation: dict[str, str] | None) -> dict:
    session = start_cloud_link(tmp_path, "gcp-posture", tenant_id="tenant-a")
    return complete_cloud_link(
        tmp_path,
        "gcp-posture",
        session_id=session["session_id"],
        actor="test",
        project_id="customer-proj",
        delegation=delegation,
    )


def test_hosted_gcp_link_stages_the_impersonation_target(tmp_path: Path) -> None:
    with server_execution(TENANT):
        result = _complete_gcp(tmp_path, {"impersonate_service_account": SERVICE_ACCOUNT})
    assert result["configure"]["credentials"] == {
        "project_id": "customer-proj",
        "impersonate_service_account": SERVICE_ACCOUNT,
    }


@pytest.mark.parametrize(
    ("delegation", "message"),
    [
        (None, "impersonate_service_account"),
        ({"impersonate_service_account": "someone@gmail.com"}, "service account email"),
        ({"impersonate_service_account": SERVICE_ACCOUNT, "client_id": CLIENT_ID}, "unexpected"),
    ],
)
def test_hosted_gcp_link_refuses_missing_or_invalid_impersonation(
    tmp_path: Path, delegation: dict[str, str] | None, message: str
) -> None:
    with server_execution(TENANT), pytest.raises(ValueError, match=message):
        _complete_gcp(tmp_path, delegation)


def test_local_gcp_link_keeps_adc_and_validates_an_optional_target(tmp_path: Path) -> None:
    assert _complete_gcp(tmp_path, None)["configure"]["credentials"] == {"project_id": "customer-proj"}
    with pytest.raises(ValueError, match="service account email"):
        _complete_gcp(tmp_path, {"impersonate_service_account": "not-an-email"})


# --- HTTP surface --------------------------------------------------------------


@pytest.fixture
def hosted_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for module in ("fastapi", "httpx", "sqlalchemy", "alembic"):
        pytest.importorskip(module)
    from fastapi.testclient import TestClient

    from security_lakehouse.db.base import session_scope
    from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
    from security_lakehouse.server_app import create_app
    from test_api_v1 import _seed_lake

    monkeypatch.setenv("GRC_LAKE_API_RATE_LIMIT_RPS", "0")
    _seed_lake(tmp_path)
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug="acme", name="Acme")
        user = create_user(session, tenant_id=tenant.id, email="admin@acme.test", role="admin")
        _key, token = create_api_key(session, tenant_id=tenant.id, user_id=user.id)
        tenant_id = tenant.id
    return TestClient(app), {"Authorization": f"Bearer {token}"}, tenant_id


def test_whoami_reports_hosted_credential_policy(hosted_client) -> None:
    client, headers, tenant_id = hosted_client
    body = client.get("/api/v1/auth/whoami", headers=headers).json()["data"]
    assert body["hosted"] is True
    assert body["secret_ref_prefix"] == tenant_secret_prefix(tenant_id)


def test_hosted_link_api_requires_delegation_and_hints_the_tenant_prefix(hosted_client) -> None:
    client, headers, tenant_id = hosted_client
    prefix = tenant_secret_prefix(tenant_id)
    assert prefix
    start = client.post("/api/v1/connectors/azure-posture/link/start", json={}, headers=headers)
    assert start.status_code == HTTPStatus.CREATED, start.text
    session = start.json()["data"]
    assert session["delegation"] == {"required": True, "secret_ref_prefix": prefix}

    missing = client.post(
        "/api/v1/connectors/azure-posture/link/complete",
        json={"session_id": session["session_id"], "subscription_id": SUBSCRIPTION},
        headers=headers,
    )
    assert missing.status_code == HTTPStatus.BAD_REQUEST
    assert "client_id" in missing.json()["errors"][0]["detail"]

    wrong_prefix = client.post(
        "/api/v1/connectors/azure-posture/link/complete",
        json={
            "session_id": session["session_id"],
            "subscription_id": SUBSCRIPTION,
            "delegation": _azure_app(client_secret_ref="AZURE_CLIENT_SECRET"),
        },
        headers=headers,
    )
    assert wrong_prefix.status_code == HTTPStatus.BAD_REQUEST
    assert prefix in wrong_prefix.json()["errors"][0]["detail"]

    ok = client.post(
        "/api/v1/connectors/azure-posture/link/complete",
        json={
            "session_id": session["session_id"],
            "subscription_id": SUBSCRIPTION,
            "delegation": _azure_app(client_secret_ref=f"{prefix}AZURE_CLIENT_SECRET"),
        },
        headers=headers,
    )
    assert ok.status_code == HTTPStatus.CREATED, ok.text
    staged = ok.json()["data"]["configure"]
    assert staged["credentials"]["client_id"] == CLIENT_ID
    assert staged["credentials"]["client_secret_ref"] == f"{prefix}AZURE_CLIENT_SECRET"


def test_delegation_payload_must_be_an_object(hosted_client) -> None:
    client, headers, _tenant_id = hosted_client
    session = client.post("/api/v1/connectors/gcp-posture/link/start", json={}, headers=headers).json()["data"]
    response = client.post(
        "/api/v1/connectors/gcp-posture/link/complete",
        json={"session_id": session["session_id"], "project_id": "customer-proj", "delegation": "x"},
        headers=headers,
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "delegation" in response.json()["errors"][0]["detail"]


def test_authenticated_server_has_no_azure_consent_callback(tmp_path: Path) -> None:
    # Server mode never issues a consent URL (collection uses the tenant's own
    # app registration), so an unauthenticated callback there would only be a
    # way to write to a lake without an identity.
    pytest.importorskip("fastapi")
    from security_lakehouse.server_app import create_app

    paths = {getattr(route, "path", "") for route in create_app(tmp_path).routes}
    assert "/api/v1/connectors/azure-posture/link/callback" not in paths
