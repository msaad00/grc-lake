"""Azure posture and Intune never collect with the server's own identity in hosted mode.

Locally ``DefaultAzureCredential`` (``az login``, managed identity, service
principal env vars) is the operator's intended identity. In server mode a tenant
names the subscription or Entra tenant, so collection must authenticate as the
tenant's own app registration (client secret, certificate, or a federated token
file) resolved through the tenant's secret-reference prefix.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from security_lakehouse import connector_runner, connectors_azure, connectors_intune, delegation
from security_lakehouse.connector_errors import ConnectorConfigError
from security_lakehouse.execution_mode import COMMERCIAL_HOSTED_ENV, server_execution
from security_lakehouse.secret_refs import SecretRefPolicyError, tenant_secret_prefix

azure_identity = pytest.importorskip("azure.identity")

TENANT = "3f2b8c1e-9a4d-4c2b-8f1e-2a6b7c8d9e0f"
PREFIX = tenant_secret_prefix(TENANT)
OTHER_PREFIX = tenant_secret_prefix("7d1c0b2a-1111-4c2b-8f1e-2a6b7c8d9e0f")
ENTRA_TENANT = "11111111-2222-3333-4444-555555555555"
APP_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
SUBSCRIPTION = "99999999-8888-7777-6666-555555555555"


@pytest.fixture(autouse=True)
def _no_hosted_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(COMMERCIAL_HOSTED_ENV, raising=False)


@pytest.fixture
def credential_log(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    """Record every azure.identity credential built; none of them touches the network."""
    log: list[tuple[str, dict[str, Any]]] = []

    def recorder(name: str) -> Any:
        class _Credential:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                log.append((name, {"args": args, **kwargs}))

            def get_token(self, *scopes: str, **kwargs: Any) -> Any:
                log.append((f"{name}.get_token", {"scopes": scopes, **kwargs}))
                return type("Token", (), {"token": f"token-from-{name}"})()

        return _Credential

    for name in (
        "DefaultAzureCredential",
        "ClientSecretCredential",
        "CertificateCredential",
        "WorkloadIdentityCredential",
    ):
        monkeypatch.setattr(azure_identity, name, recorder(name))
    return log


@pytest.fixture
def no_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_: Any, **__: Any) -> Any:
        raise AssertionError("the az CLI (the server's own login) must not be used in server mode")

    monkeypatch.setattr(connectors_azure, "AzureCliClient", refuse)
    monkeypatch.setattr(connectors_azure, "AzureCliClient", refuse)


def _delegated(**extra: str) -> dict[str, str]:
    return {"subscription_id": SUBSCRIPTION, "tenant_id": ENTRA_TENANT, "client_id": APP_ID, **extra}


def _names(log: list[tuple[str, dict[str, Any]]]) -> list[str]:
    return [name for name, _ in log]


# --- delegation.azure_credential ----------------------------------------------


def test_server_mode_refuses_the_ambient_identity(credential_log, no_cli) -> None:
    with server_execution(TENANT), pytest.raises(ConnectorConfigError, match="client_id"):
        delegation.azure_credential({"subscription_id": SUBSCRIPTION}, {}, label="azure-posture")
    assert credential_log == []


def test_local_mode_keeps_default_azure_credential(credential_log) -> None:
    assert delegation.azure_credential({"subscription_id": SUBSCRIPTION}, {}, label="azure-posture") is None


def test_server_mode_builds_a_client_secret_credential_from_the_tenant_prefix(credential_log) -> None:
    env = {f"{PREFIX}AZURE_SECRET": "tenant-app-secret"}
    creds = _delegated(client_secret_ref=f"{PREFIX}AZURE_SECRET")
    with server_execution(TENANT):
        delegation.azure_credential(creds, env, label="azure-posture")
    assert credential_log == [
        ("ClientSecretCredential", {"args": (ENTRA_TENANT, APP_ID, "tenant-app-secret")}),
    ]


def test_server_mode_builds_a_certificate_credential(credential_log) -> None:
    pem = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----"
    env = {f"{PREFIX}AZURE_CERT": pem}
    with server_execution(TENANT):
        delegation.azure_credential(
            _delegated(client_certificate_ref=f"{PREFIX}AZURE_CERT"), env, label="azure-posture"
        )
    name, call = credential_log[0]
    assert name == "CertificateCredential"
    assert call["args"] == (ENTRA_TENANT, APP_ID)
    assert call["certificate_data"] == pem.encode()


def test_server_mode_builds_a_workload_identity_credential(credential_log, tmp_path: Path) -> None:
    token_file = tmp_path / "azure-federated-token"
    token_file.write_text("header.payload.sig", encoding="utf-8")
    env = {f"{PREFIX}AZURE_TOKEN_FILE": str(token_file)}
    with server_execution(TENANT):
        delegation.azure_credential(
            _delegated(federated_token_file_ref=f"{PREFIX}AZURE_TOKEN_FILE"), env, label="azure-posture"
        )
    assert credential_log == [
        (
            "WorkloadIdentityCredential",
            {"args": (), "tenant_id": ENTRA_TENANT, "client_id": APP_ID, "token_file_path": str(token_file)},
        )
    ]


@pytest.mark.parametrize("ref", ["AZURE_CLIENT_SECRET", "TRUSTOPS_COOKIE_SIGNING_KEY"])
def test_server_secrets_are_refused_as_the_client_secret(ref: str, credential_log) -> None:
    env = {ref: "server-value"}
    with server_execution(TENANT), pytest.raises(SecretRefPolicyError):
        delegation.azure_credential(_delegated(client_secret_ref=ref), env, label="azure-posture")
    assert credential_log == []


def test_another_tenants_secret_is_refused(credential_log) -> None:
    ref = f"{OTHER_PREFIX}AZURE_SECRET"
    with server_execution(TENANT), pytest.raises(SecretRefPolicyError):
        delegation.azure_credential(_delegated(client_secret_ref=ref), {ref: "other"}, label="azure-posture")
    assert credential_log == []


def test_an_unset_tenant_secret_is_a_config_error(credential_log) -> None:
    with server_execution(TENANT), pytest.raises(ConnectorConfigError, match="client_secret_ref"):
        delegation.azure_credential(_delegated(client_secret_ref=f"{PREFIX}AZURE_SECRET"), {}, label="azure-posture")
    assert credential_log == []


@pytest.mark.parametrize(
    "creds",
    [
        {"client_id": APP_ID, "client_secret_ref": f"{PREFIX}S"},  # no tenant_id
        {"tenant_id": ENTRA_TENANT, "client_secret_ref": f"{PREFIX}S"},  # no client_id
        {"tenant_id": ENTRA_TENANT, "client_id": APP_ID},  # no secret, cert, or token file
        {
            "tenant_id": ENTRA_TENANT,
            "client_id": APP_ID,
            "client_secret_ref": f"{PREFIX}S",
            "client_certificate_ref": f"{PREFIX}C",
        },
        {"tenant_id": "evil/../x", "client_id": APP_ID, "client_secret_ref": f"{PREFIX}S"},
    ],
)
def test_incomplete_or_ambiguous_delegation_is_refused(creds: dict[str, str], credential_log) -> None:
    env = {f"{PREFIX}S": "s", f"{PREFIX}C": "c"}
    with server_execution(TENANT), pytest.raises(ConnectorConfigError):
        delegation.azure_credential(creds, env, label="azure-posture")
    assert credential_log == []


# --- azure-posture sync and probe ------------------------------------------------


def test_azure_sync_refuses_ambient_identity_and_env_overrides_in_server_mode(credential_log, no_cli) -> None:
    env = {"AZURE_SUBSCRIPTION_ID": SUBSCRIPTION}
    with server_execution(TENANT), pytest.raises(ConnectorConfigError, match="subscription_id"):
        connector_runner._collect_azure(fixture_dir=None, env=env, credentials={})
    with server_execution(TENANT), pytest.raises(ConnectorConfigError, match="client_id"):
        connector_runner._collect_azure(fixture_dir=None, env={}, credentials={"subscription_id": SUBSCRIPTION})
    assert credential_log == []


def test_azure_sync_collects_as_the_tenant_app_in_server_mode(monkeypatch, credential_log, no_cli) -> None:
    built: list[tuple[str, Any]] = []

    class _Client:
        def __init__(self, subscription_id: str, *, credential: Any = None) -> None:
            built.append((subscription_id, credential))
            self.subscription_id = subscription_id

    monkeypatch.setattr(connectors_azure, "AzureClient", _Client)
    monkeypatch.setattr(connector_runner, "collect_azure_evidence", lambda client: [])
    env = {f"{PREFIX}AZURE_SECRET": "tenant-app-secret", "AZURE_SUBSCRIPTION_ID": "operator-subscription"}
    with server_execution(TENANT):
        connector_runner._collect_azure(
            fixture_dir=None, env=env, credentials=_delegated(client_secret_ref=f"{PREFIX}AZURE_SECRET")
        )
    assert [sub for sub, _ in built] == [SUBSCRIPTION]
    assert built[0][1] is not None
    assert _names(credential_log) == ["ClientSecretCredential"]


def test_azure_sync_local_mode_keeps_env_override_and_default_credential(monkeypatch, credential_log) -> None:
    built: list[tuple[str, Any]] = []

    class _Client:
        def __init__(self, subscription_id: str, *, credential: Any = None) -> None:
            built.append((subscription_id, credential))

    monkeypatch.setattr(connectors_azure, "AzureClient", _Client)
    monkeypatch.setattr(connector_runner, "collect_azure_evidence", lambda client: [])
    connector_runner._collect_azure(
        fixture_dir=None, env={"AZURE_SUBSCRIPTION_ID": "operator-subscription"}, credentials={}
    )
    assert built == [("operator-subscription", None)]


def test_azure_client_uses_default_credential_only_without_a_delegated_one(credential_log) -> None:
    pytest.importorskip("azure.mgmt.authorization")
    connectors_azure.AzureClient(SUBSCRIPTION)
    delegated = object()
    connectors_azure.AzureClient(SUBSCRIPTION, credential=delegated)
    assert _names(credential_log) == ["DefaultAzureCredential"]


def test_azure_probe_refuses_ambient_identity_in_server_mode(credential_log, no_cli) -> None:
    with server_execution(TENANT), pytest.raises(ConnectorConfigError, match="client_id"):
        connectors_azure.probe_azure_access(credentials={"subscription_id": SUBSCRIPTION}, options={})
    assert credential_log == []


def test_azure_probe_never_falls_back_to_the_cli_in_server_mode(monkeypatch, credential_log, no_cli) -> None:
    def missing_sdk(*_: Any, **__: Any) -> Any:
        raise ConnectorConfigError("azure-posture live collection requires azure-identity")

    monkeypatch.setattr(connectors_azure, "AzureClient", missing_sdk)
    monkeypatch.setenv(f"{PREFIX}AZURE_SECRET", "tenant-app-secret")
    with server_execution(TENANT), pytest.raises(ConnectorConfigError, match="azure-identity"):
        connectors_azure.probe_azure_access(
            credentials=_delegated(client_secret_ref=f"{PREFIX}AZURE_SECRET"), options={}
        )


def test_azure_probe_uses_the_tenant_app_in_server_mode(monkeypatch, credential_log, no_cli) -> None:
    class _Client:
        def __init__(self, subscription_id: str, *, credential: Any = None) -> None:
            assert credential is not None
            self.subscription_id = subscription_id

        def subscription(self) -> dict[str, Any]:
            return {"state": "Enabled"}

    monkeypatch.setattr(connectors_azure, "AzureClient", _Client)
    monkeypatch.setenv(f"{PREFIX}AZURE_SECRET", "tenant-app-secret")
    with server_execution(TENANT):
        result = connectors_azure.probe_azure_access(
            credentials=_delegated(client_secret_ref=f"{PREFIX}AZURE_SECRET"), options={}
        )
    assert result["ok"] is True and result["subscription_state"] == "Enabled"
    assert _names(credential_log) == ["ClientSecretCredential"]


# --- intune-devices ---------------------------------------------------------------


def test_intune_sync_refuses_ambient_identity_and_env_tenant_in_server_mode(credential_log) -> None:
    with server_execution(TENANT), pytest.raises(ConnectorConfigError, match="tenant_id"):
        connector_runner._collect_intune(fixture_dir=None, env={"AZURE_TENANT_ID": ENTRA_TENANT}, credentials={})
    with server_execution(TENANT), pytest.raises(ConnectorConfigError, match="client_id"):
        connector_runner._collect_intune(fixture_dir=None, env={}, credentials={"tenant_id": ENTRA_TENANT})
    assert credential_log == []


def test_intune_client_refuses_default_credential_in_server_mode(credential_log) -> None:
    with server_execution(TENANT), pytest.raises(ConnectorConfigError):
        connectors_intune.IntuneClient(ENTRA_TENANT)
    assert credential_log == []


def test_intune_sync_uses_the_tenant_app_token_in_server_mode(monkeypatch, credential_log) -> None:
    captured: list[connectors_intune.IntuneClient] = []
    monkeypatch.setattr(connector_runner, "collect_intune_evidence", lambda client: captured.append(client) or [])
    env = {f"{PREFIX}GRAPH_SECRET": "tenant-app-secret"}
    creds = {"tenant_id": ENTRA_TENANT, "client_id": APP_ID, "client_secret_ref": f"{PREFIX}GRAPH_SECRET"}
    with server_execution(TENANT):
        connector_runner._collect_intune(fixture_dir=None, env=env, credentials=creds)
    client = captured[0]
    assert client.tenant_id == ENTRA_TENANT
    assert client._token_provider() == "token-from-ClientSecretCredential"
    assert credential_log[-1] == ("ClientSecretCredential.get_token", {"scopes": (connectors_intune.GRAPH_SCOPE,)})


def test_intune_local_mode_keeps_default_credential(credential_log) -> None:
    client = connectors_intune.IntuneClient(ENTRA_TENANT)
    assert client._token_provider() == "token-from-DefaultAzureCredential"
    assert credential_log[-1] == (
        "DefaultAzureCredential.get_token",
        {"scopes": (connectors_intune.GRAPH_SCOPE,), "tenant_id": ENTRA_TENANT},
    )
