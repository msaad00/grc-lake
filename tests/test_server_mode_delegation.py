"""Hosted server mode never collects with the server's own identity or disk.

Locally the operator's ambient credentials (SSO profile, instance role, ADC,
in-cluster service account, kubeconfig) are the point. In server mode a tenant
chooses the target account/project/cluster, so every reader must use explicit,
tenant-delegated access: an AWS role with an external id, a GCP service account
to impersonate, a named kubeconfig. Local paths are scoped per tenant.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from security_lakehouse import connectors_iceberg as ice
from security_lakehouse.connector_errors import ConnectorConfigError
from security_lakehouse.execution_mode import COMMERCIAL_HOSTED_ENV, server_execution

ROLE = "arn:aws:iam::111122223333:role/trustops-reader"
TENANT = "3f2b8c1e-9a4d-4c2b-8f1e-2a6b7c8d9e0f"


@pytest.fixture(autouse=True)
def _no_hosted_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(COMMERCIAL_HOSTED_ENV, raising=False)


@pytest.fixture
def no_boto(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record any boto3 use; the checks must fail before touching AWS."""
    boto3 = pytest.importorskip("boto3")
    calls: list[str] = []

    def client(name: str, **_: Any) -> Any:
        calls.append(name)
        raise AssertionError(f"boto3 client {name} created before delegation was checked")

    class Session:
        def __init__(self, **_: Any) -> None:
            calls.append("session")

        def client(self, name: str, **kw: Any) -> Any:
            return client(name, **kw)

    monkeypatch.setattr(boto3, "client", client)
    monkeypatch.setattr(boto3, "Session", Session)
    return calls


# --- AWS ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role_arn", "external_id"),
    [(None, None), (ROLE, None), (None, "ext-1")],
)
def test_aws_clients_require_role_and_external_id_in_server_mode(
    role_arn: str | None, external_id: str | None, no_boto: list[str]
) -> None:
    from security_lakehouse.connectors_aws import AWSClient
    from security_lakehouse.connectors_s3 import S3Client

    with server_execution(TENANT):
        with pytest.raises(ConnectorConfigError, match="external_id"):
            AWSClient(region_name="us-east-1", role_arn=role_arn, external_id=external_id)
        with pytest.raises(ConnectorConfigError, match="external_id"):
            S3Client(bucket="b", prefix="", role_arn=role_arn, external_id=external_id)
    assert no_boto == []


def test_aws_posture_sync_ignores_server_env_role_override(no_boto: list[str]) -> None:
    from security_lakehouse.connector_runner import _collect_aws

    env = {"AWS_ROLE_ARN": ROLE, "AWS_EXTERNAL_ID": "operator-ext"}
    with server_execution(TENANT), pytest.raises(ConnectorConfigError, match="external_id"):
        _collect_aws(fixture_dir=None, env=env, credentials={"account_id": "111122223333"})


def test_aws_probe_requires_external_id_in_server_mode(no_boto: list[str]) -> None:
    from security_lakehouse.connectors_aws import probe_aws_access

    with server_execution(TENANT), pytest.raises(ConnectorConfigError, match="external_id"):
        probe_aws_access(credentials={"account_id": "111122223333", "role_arn": ROLE}, options={})


def test_iceberg_assume_role_and_glue_require_external_id_in_server_mode(no_boto: list[str]) -> None:
    with server_execution(TENANT):
        with pytest.raises(ConnectorConfigError, match="external_id"):
            ice._assume_role(ROLE, None, "us-east-1")
        with pytest.raises(ConnectorConfigError, match="external_id"):
            ice.build_reader({"catalog_type": "glue", "region": "us-east-1"}, {}, env={})
        with pytest.raises(ConnectorConfigError, match="external_id"):
            ice.build_reader(
                {"catalog_type": "parquet", "path": "s3://bucket/prefix", "region": "us-east-1"}, {}, env={}
            )
    assert no_boto == []


def test_local_mode_keeps_ambient_aws_for_cli(no_boto: list[str]) -> None:
    from security_lakehouse.connectors_s3 import S3Client

    with pytest.raises(AssertionError, match="before delegation"):
        S3Client(bucket="b", prefix="")  # reaches boto3: ambient chain allowed locally


# --- Iceberg REST credential in server mode -----------------------------------


def test_iceberg_rest_default_token_env_needs_explicit_ref_in_server_mode() -> None:
    creds = {"catalog_type": "rest", "uri": "https://catalog.example.com/api", "warehouse": "w"}
    with server_execution(TENANT), pytest.raises(ConnectorConfigError, match="credential_ref"):
        ice.build_reader(creds, {"mapping": {}}, env={"TRUSTOPS_ICEBERG_TOKEN": "operator"})
    with server_execution(TENANT), pytest.raises(ConnectorConfigError, match="server secret"):
        ice.build_reader({**creds, "credential_ref": "DATABASE_URL"}, {}, env={"DATABASE_URL": "x"})


# --- local lake root ------------------------------------------------------------


def test_local_parquet_paths_are_scoped_to_the_tenant_in_server_mode(tmp_path: Path) -> None:
    root = tmp_path / "lakes"
    own = root / TENANT / "events"
    other = root / "other-tenant" / "events"
    own.mkdir(parents=True)
    other.mkdir(parents=True)
    env = {"TRUSTOPS_LAKE_LOCAL_ROOT": str(root)}
    with server_execution(TENANT):
        assert ice._parse_location(str(own), env) == ("local", str(own.resolve()))
        with pytest.raises(ValueError, match="tenant"):
            ice._parse_location(str(other), env)
        with pytest.raises(ValueError, match="tenant"):
            ice._parse_location(str(root), env)
    with server_execution(None), pytest.raises(ValueError, match="tenant"):
        ice._parse_location(str(own), env)
    # Local/CLI mode keeps the whole root.
    assert ice._parse_location(str(other), env) == ("local", str(other.resolve()))


# --- Kubernetes ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("credentials", "env"),
    [
        ({"cluster_name": "c", "in_cluster": True}, {}),
        ({"cluster_name": "c"}, {"KUBERNETES_SERVICE_HOST": "10.0.0.1"}),
        ({"cluster_name": "c"}, {"KUBECONFIG": "/root/.kube/config"}),
    ],
)
def test_kubernetes_server_identity_is_refused_in_server_mode(
    credentials: dict[str, Any], env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from security_lakehouse import connector_runner

    def fail(*_: Any, **__: Any) -> Any:
        raise AssertionError("kubernetes client built")

    monkeypatch.setattr(connector_runner, "KubernetesClient", fail)
    with server_execution(TENANT), pytest.raises(ConnectorConfigError, match="kubeconfig_ref"):
        connector_runner._collect_kubernetes(fixture_dir=None, env=env, credentials=credentials)


def test_kubernetes_tenant_kubeconfig_ref_is_used_in_server_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    from security_lakehouse import connector_runner

    seen: dict[str, Any] = {}

    class FakeClient:
        def __init__(self, cluster: str, **kwargs: Any) -> None:
            seen.update(kwargs)

    monkeypatch.setattr(connector_runner, "KubernetesClient", FakeClient)
    monkeypatch.setattr(connector_runner, "collect_kubernetes_evidence", lambda *a, **k: [])
    prefix = "TRUSTOPS_TENANT_3F2B8C1E_9A4D_4C2B_8F1E_2A6B7C8D9E0F__"
    env = {f"{prefix}KUBECONFIG": "/secrets/tenant/kubeconfig", "KUBERNETES_SERVICE_HOST": "10.0.0.1"}
    with server_execution(TENANT):
        connector_runner._collect_kubernetes(
            fixture_dir=None, env=env, credentials={"cluster_name": "c", "kubeconfig_ref": f"{prefix}KUBECONFIG"}
        )
    assert seen == {"context": None, "kubeconfig_path": "/secrets/tenant/kubeconfig", "in_cluster": False}


# --- GCP / BigQuery -------------------------------------------------------------


def test_gcp_probe_requires_impersonation_target_in_server_mode() -> None:
    from security_lakehouse.connectors_gcp import probe_gcp_access

    with server_execution(TENANT), pytest.raises(ConnectorConfigError, match="impersonate_service_account"):
        probe_gcp_access(credentials={"project_id": "tenant-proj"}, options={})


def test_gcp_delegated_credentials_impersonate_the_named_service_account(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("google.auth")
    import google.auth
    from google.auth import impersonated_credentials

    from security_lakehouse.delegation import gcp_credentials

    captured: dict[str, Any] = {}
    monkeypatch.setattr(google.auth, "default", lambda scopes=None: ("server-adc", "server-project"))

    class FakeImpersonated:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(impersonated_credentials, "Credentials", FakeImpersonated)
    sa = "trustops-reader@tenant-proj.iam.gserviceaccount.com"
    with server_execution(TENANT):
        creds = gcp_credentials({"impersonate_service_account": sa})
    assert isinstance(creds, FakeImpersonated)
    assert captured["source_credentials"] == "server-adc"
    assert captured["target_principal"] == sa
    assert captured["target_scopes"] == ["https://www.googleapis.com/auth/cloud-platform"]
    with pytest.raises(ConnectorConfigError, match="impersonate_service_account"):
        gcp_credentials({"impersonate_service_account": "not-an-email"})
    assert gcp_credentials({}) is None  # local mode: ADC


def test_bigquery_requires_impersonation_and_same_project_tables_in_server_mode() -> None:
    pytest.importorskip("google.cloud.bigquery")
    from google.auth.credentials import AnonymousCredentials

    from security_lakehouse import connectors_bigquery as bq
    from security_lakehouse.lake_mapping import resolve_mapping_ref

    with server_execution(TENANT), pytest.raises(ConnectorConfigError, match="impersonate_service_account"):
        bq.client_from_config({"project_id": "tenant-proj"}, {})

    client = bq.BigQueryClient("tenant-proj", dataset="ds", credentials=AnonymousCredentials())
    foreign = resolve_mapping_ref({"preset": "ocsf/compliance_finding", "source": {"table": "operator-proj.ds.t"}})
    with server_execution(TENANT), pytest.raises(ConnectorConfigError, match="project"):
        client.fetch_mapping_rows(foreign, since=None, limit=10)
    opted_in = bq.BigQueryClient(
        "tenant-proj", dataset="ds", credentials=AnonymousCredentials(), allow_cross_project=True
    )
    assert opted_in.allow_cross_project is True
