"""Tests for one-click AWS/Azure cloud account linking."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from security_lakehouse.cloud_linking import (
    aws_quick_create_url,
    aws_template_bytes,
    aws_template_url,
    aws_terraform_bytes,
    azure_callback_redirect,
    azure_consent_url,
    complete_cloud_link,
    gcp_deploy_command,
    gcp_template_bytes,
    get_cloud_link_session,
    issue_cloud_link_redirect_token,
    normalize_link_session_id,
    record_azure_consent,
    resolve_cloud_link_session_id,
    start_cloud_link,
    valid_gcp_project_id,
)
from test_api_v1 import _request, _spin


def test_aws_template_bytes_is_packaged() -> None:
    body = aws_template_bytes()
    assert b"TrustOpsPostureReadOnlyRole" in body
    assert b"TrustedPrincipalArn" in body


def test_aws_terraform_bytes_is_packaged() -> None:
    body = aws_terraform_bytes()
    assert b'variable "trusted_principal_arn"' in body
    assert b"aws_iam_role" in body
    assert b"role_arn" in body


def test_aws_template_url_uses_external_https_override(monkeypatch: pytest.MonkeyPatch) -> None:
    external = "https://templates.example.com/trustops/aws-readonly.yaml"
    monkeypatch.setenv("TRUSTOPS_AWS_TEMPLATE_URL", external)

    assert aws_template_url("http://127.0.0.1:8787") == external


def test_aws_template_url_rejects_non_https_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_AWS_TEMPLATE_URL", "http://templates.example.com/aws.yaml")

    assert aws_template_url("http://127.0.0.1:8787") is None


def test_gcp_template_bytes_is_packaged() -> None:
    body = gcp_template_bytes()
    assert b"trustops-posture-reader" in body
    assert b"workload_identity_member" in body


def test_valid_gcp_project_id() -> None:
    assert valid_gcp_project_id("my-gcp-project")
    assert not valid_gcp_project_id("bad project")
    assert not valid_gcp_project_id("x")


def test_gcp_deploy_command_includes_wif_member(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_GCP_WIF_MEMBER", "serviceAccount:demo.svc.id.goog[ns/sa]")
    cmd = gcp_deploy_command(project_id="demo-project")
    assert "demo-project" in cmd
    assert "workload_identity_member=serviceAccount:demo.svc.id.goog[ns/sa]" in cmd


def test_normalize_link_session_id_rejects_unsafe_tokens() -> None:
    assert normalize_link_session_id("valid-session_01") == "valid-session_01"
    assert normalize_link_session_id("bad\r\nsession") is None
    assert normalize_link_session_id("../../etc/passwd") is None


def test_azure_callback_redirect_ignores_unsafe_session_ids() -> None:
    url = azure_callback_redirect(
        session_id="bad\r\nsession",
        public_url="https://demo.example.com",
    )
    assert url == "https://demo.example.com/console/connectors/?connect=azure-posture"
    assert "link_session" not in url


def test_aws_quick_create_url_includes_external_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_AWS_LINK_PRINCIPAL", "arn:aws:iam::111122223333:role/TrustOpsLink")
    url = aws_quick_create_url(
        external_id="ext-abc123",
        public_url="https://demo.example.com",
    )
    assert url is not None
    fragment = urlparse(url).fragment
    assert "quickcreate?" in fragment
    query = fragment.split("?", 1)[1]
    params = parse_qs(query)
    assert "templateURL" in params
    assert params["param_ExternalId"] == ["ext-abc123"]
    assert params["param_TrustedPrincipalArn"] == ["arn:aws:iam::111122223333:role/TrustOpsLink"]


def test_azure_consent_url_when_client_id_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_AZURE_LINK_CLIENT_ID", "azure-client-id")
    url = azure_consent_url(session_id="sess-1", public_url="https://demo.example.com")
    assert url is not None
    assert "login.microsoftonline.com/common/adminconsent" in url
    assert "client_id=azure-client-id" in url
    assert "state=sess-1" in url


def test_azure_link_session_exposes_configured_non_secret_app_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TRUSTOPS_AZURE_LINK_CLIENT_ID", "azure-client-id")
    session = start_cloud_link(tmp_path, "azure-posture", tenant_id="tenant-a")

    assert session["azure_app_id"] == "azure-client-id"
    assert session["runtime_identity_ready"] is True


def test_start_and_complete_aws_cloud_link_stages_connector(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_AWS_LINK_PRINCIPAL", "arn:aws:iam::111122223333:role/TrustOpsLink")
    monkeypatch.setenv("TRUSTOPS_PUBLIC_URL", "https://demo.example.com")
    session = start_cloud_link(tmp_path, "aws-posture", tenant_id="tenant-a")
    assert session["runtime_identity_ready"] is True
    assert session["cloudshell_command"]
    assert "127.0.0.1" not in session["cloudshell_command"]
    assert "localhost" not in session["cloudshell_command"]
    assert "YOUR_TRUSTOPS_PRINCIPAL_ARN" not in session["cloudshell_command"]
    assert "base64" in session["cloudshell_command"]
    assert session["external_id"]
    assert session["quick_create_url"]
    assert session["terraform_url"] == "https://demo.example.com/api/v1/connectors/aws-posture/link/terraform.tf"
    assert session["manual_terraform_path"] == "deploy/aws/trustops-posture-readonly-role.tf"
    assert session["account_scope"] == "aws_account"
    assert session["deployment_methods"] == [
        {
            "id": "console",
            "label": "AWS Console",
            "detail": "Guided CloudFormation",
        },
        {
            "id": "cloudformation",
            "label": "CloudFormation CLI",
            "detail": "AWS CLI stack deploy",
        },
        {
            "id": "terraform",
            "label": "Terraform CLI",
            "detail": "IaC workspace rollout",
        },
    ]
    assert session["scale_strategy"]["mode"] == "stacksets_or_terraform"
    assert "CloudFormation StackSets" in session["scale_strategy"]["summary"]
    assert "Terraform workspaces" in session["scale_strategy"]["summary"]


def test_aws_cloud_link_fails_closed_without_runtime_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TRUSTOPS_AWS_LINK_PRINCIPAL", raising=False)
    session = start_cloud_link(tmp_path, "aws-posture", tenant_id="tenant-a", public_url="http://127.0.0.1:8787")

    assert session["runtime_identity_ready"] is False
    assert session["trusted_principal"] is None
    assert session["cloudshell_command"] is None
    assert session["quick_create_url"] is None
    assert "Bulk account import" in session["scale_strategy"]["follow_up"]

    result = complete_cloud_link(
        tmp_path,
        "aws-posture",
        session_id=session["session_id"],
        actor="test",
        role_arn="arn:aws:iam::123456789012:role/TrustOpsPostureReadOnlyRole",
    )
    configure = result["configure"]
    assert configure["connector_id"] == "aws-posture"
    assert configure["state"] == "disabled"
    assert configure["credentials"]["account_id"] == "123456789012"
    assert configure["credentials"]["role_arn"] == "arn:aws:iam::123456789012:role/TrustOpsPostureReadOnlyRole"
    assert configure["credentials"]["external_id"] == session["external_id"]


@pytest.mark.parametrize(
    "role_arn",
    [
        "",
        "123456789012",
        "arn:aws:iam::123456789012:user/not-a-role",
        "arn:aws:iam::not-an-account:role/TrustOpsPostureReadOnlyRole",
    ],
)
def test_complete_aws_cloud_link_rejects_invalid_role_arn(tmp_path: Path, role_arn: str) -> None:
    session = start_cloud_link(tmp_path, "aws-posture", tenant_id="tenant-a")

    with pytest.raises(ValueError, match="role_arn"):
        complete_cloud_link(
            tmp_path,
            "aws-posture",
            session_id=session["session_id"],
            actor="test",
            role_arn=role_arn,
        )


def test_azure_consent_callback_and_complete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_AZURE_LINK_CLIENT_ID", "azure-client-id")
    monkeypatch.setenv("TRUSTOPS_PUBLIC_URL", "https://demo.example.com")
    session = start_cloud_link(tmp_path, "azure-posture", tenant_id="tenant-a")
    record_azure_consent(
        tmp_path,
        session_id=session["session_id"],
        azure_tenant_id="tenant-guid",
        admin_consent=True,
    )
    updated = get_cloud_link_session(tmp_path, session["session_id"])
    assert updated is not None
    assert updated["azure_tenant_id"] == "tenant-guid"
    assert updated["status"] == "consented"

    result = complete_cloud_link(
        tmp_path,
        "azure-posture",
        session_id=session["session_id"],
        actor="test",
        subscription_id="11111111-2222-3333-4444-555555555555",
    )
    configure = result["configure"]
    assert configure["credentials"]["subscription_id"] == "11111111-2222-3333-4444-555555555555"
    assert "azure_tenant_id" not in configure["options"]


def test_azure_consent_can_complete_with_server_redirect_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_AZURE_LINK_CLIENT_ID", "azure-client-id")
    session = start_cloud_link(tmp_path, "azure-posture", tenant_id="tenant-a")
    record_azure_consent(
        tmp_path,
        session_id=session["session_id"],
        azure_tenant_id="tenant-guid",
        admin_consent=True,
    )

    redirect_token = issue_cloud_link_redirect_token(tmp_path, session_id=session["session_id"])
    assert redirect_token != session["session_id"]
    assert resolve_cloud_link_session_id(tmp_path, redirect_token) == session["session_id"]
    redirect_url = azure_callback_redirect(session_id=redirect_token, public_url="https://demo.example.com")
    params = parse_qs(urlparse(redirect_url).query)
    assert params["link_session"] == [redirect_token]

    result = complete_cloud_link(
        tmp_path,
        "azure-posture",
        session_id=redirect_token,
        actor="test",
        subscription_id="11111111-2222-3333-4444-555555555555",
    )
    configure = result["configure"]
    assert configure["credentials"]["subscription_id"] == "11111111-2222-3333-4444-555555555555"
    assert "azure_tenant_id" not in configure["options"]


def test_start_and_complete_gcp_cloud_link_stages_connector(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_PUBLIC_URL", "https://demo.example.com")
    monkeypatch.setenv("TRUSTOPS_GCP_WIF_MEMBER", "serviceAccount:demo.svc.id.goog[ns/sa]")
    session = start_cloud_link(tmp_path, "gcp-posture", tenant_id="tenant-a")
    assert session["template_url"]
    assert session["deploy_command"]
    assert session["workload_identity_member"]

    result = complete_cloud_link(
        tmp_path,
        "gcp-posture",
        session_id=session["session_id"],
        actor="test",
        project_id="my-gcp-project",
    )
    configure = result["configure"]
    assert configure["connector_id"] == "gcp-posture"
    assert configure["state"] == "disabled"
    assert configure["credentials"]["project_id"] == "my-gcp-project"


def test_v1_cloud_link_start_and_complete_api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_AWS_LINK_PRINCIPAL", "arn:aws:iam::111122223333:role/TrustOpsLink")
    monkeypatch.setenv("TRUSTOPS_PUBLIC_URL", "https://demo.example.com")
    server = _spin(tmp_path)
    try:
        status, body = _request(
            server,
            "POST",
            "/api/v1/connectors/aws-posture/link/start",
            {"public_url": "https://demo.example.com"},
        )
        assert status == HTTPStatus.CREATED
        assert body["meta"]["resource"] == "connector.link.start"
        session_id = body["data"]["session_id"]

        complete_status, complete_body = _request(
            server,
            "POST",
            "/api/v1/connectors/aws-posture/link/complete",
            {
                "session_id": session_id,
                "role_arn": "arn:aws:iam::123456789012:role/TrustOpsPostureReadOnlyRole",
            },
        )
        assert complete_status == HTTPStatus.CREATED
        assert complete_body["data"]["configure"]["credentials"]["account_id"] == "123456789012"
    finally:
        server.shutdown()


def test_v1_catalog_advertises_cloud_link_actions(tmp_path: Path) -> None:
    server = _spin(tmp_path)
    try:
        status, body = _request(server, "GET", "/api/v1")
        assert status == HTTPStatus.OK
        by_path = {item["path"]: item for item in body["data"]["resources"]}
        assert by_path["/api/v1/connectors/{connector_id}/link/start"]["resource"] == "connector.link.start"
        assert by_path["/api/v1/connectors/{connector_id}/link/complete"]["resource"] == "connector.link.complete"
    finally:
        server.shutdown()


def test_aws_template_endpoint_serves_yaml(tmp_path: Path) -> None:
    server = _spin(tmp_path)
    try:
        import http.client

        host, port = server.server_address
        conn = http.client.HTTPConnection(host, port, timeout=30)
        conn.request("GET", "/api/v1/connectors/aws-posture/link/template.yaml")
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        assert resp.status == HTTPStatus.OK
        assert b"TrustOpsPostureReadOnlyRole" in raw
    finally:
        server.shutdown()


def test_aws_terraform_endpoint_serves_tf(tmp_path: Path) -> None:
    server = _spin(tmp_path)
    try:
        import http.client

        host, port = server.server_address
        conn = http.client.HTTPConnection(host, port, timeout=30)
        conn.request("GET", "/api/v1/connectors/aws-posture/link/terraform.tf")
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        assert resp.status == HTTPStatus.OK
        assert b'variable "external_id"' in raw
        assert b"TrustOpsPostureReadOnly" in raw
    finally:
        server.shutdown()


def test_gcp_template_endpoint_serves_tf(tmp_path: Path) -> None:
    server = _spin(tmp_path)
    try:
        import http.client

        host, port = server.server_address
        conn = http.client.HTTPConnection(host, port, timeout=30)
        conn.request("GET", "/api/v1/connectors/gcp-posture/link/template.tf")
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        assert resp.status == HTTPStatus.OK
        assert b"trustops-posture-reader" in raw
    finally:
        server.shutdown()


def test_azure_link_rejects_a_subscription_id_that_is_not_a_guid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TRUSTOPS_AZURE_LINK_CLIENT_ID", "azure-client-id")
    session = start_cloud_link(tmp_path, "azure-posture", tenant_id="tenant-a")
    with pytest.raises(ValueError, match="subscription_id"):
        complete_cloud_link(
            tmp_path,
            "azure-posture",
            session_id=session["session_id"],
            actor="test",
            subscription_id="Zq8~sUpErSeCrEt.value_123",
        )
    assert not (tmp_path / "gold" / "connector_config.jsonl").exists()


def test_a_completed_link_session_cannot_be_completed_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTOPS_GCP_WIF_MEMBER", "serviceAccount:demo.svc.id.goog[ns/sa]")
    session = start_cloud_link(tmp_path, "gcp-posture", tenant_id="tenant-a")
    complete_cloud_link(tmp_path, "gcp-posture", session_id=session["session_id"], actor="a", project_id="first-proj")
    with pytest.raises(ValueError, match="already completed"):
        complete_cloud_link(
            tmp_path, "gcp-posture", session_id=session["session_id"], actor="b", project_id="second-proj"
        )
    events = (tmp_path / "gold" / "connector_config.jsonl").read_text().splitlines()
    assert len(events) == 1
