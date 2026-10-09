"""One-click AWS/Azure/GCP account linking for managed-GRC-style connector onboarding.

AWS linking issues a tenant-scoped external ID and a CloudFormation quick-create
URL against the read-only posture role template in ``deploy/aws/``. AWS and GCP
also serve Terraform templates for teams that prefer IaC. Locally, Azure linking
builds an admin-consent URL when ``GRC_LAKE_AZURE_LINK_CLIENT_ID`` is set.

In hosted server mode the server never collects with its own cloud identity
(see :mod:`security_lakehouse.delegation`), so a link session reports the
delegation it needs and completion stages the tenant's own Azure app
registration or GCP impersonation target, validated with the readers' rules.
No server-owned Azure consent app is offered there. The Entra tenant an
unauthenticated consent callback reports is kept on the session for display
only and is never written into a connector config.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from security_lakehouse.connector_errors import ConnectorConfigError
from security_lakehouse.connector_state import append_config_event
from security_lakehouse.delegation import (
    AZURE_SECRET_FIELDS,
    GCP_IMPERSONATION_FIELD,
    azure_app_registration,
    gcp_impersonation_target,
)
from security_lakehouse.execution_mode import in_server_mode, server_tenant_id
from security_lakehouse.io import read_json, write_json
from security_lakehouse.models import utc_iso
from security_lakehouse.public_url import normalize_public_url
from security_lakehouse.runtime_environment import runtime_env
from security_lakehouse.secret_refs import ENV_NAME_RE, secret_ref_denial, tenant_secret_prefix

CLOUD_LINK_CONNECTORS = frozenset({"aws-posture", "azure-posture", "gcp-posture"})
AWS_ROLE_NAME_DEFAULT = "GrcLakePostureReadOnlyRole"
AWS_TEMPLATE_REL = Path("deploy/aws/grc-lake-posture-readonly-role.yaml")
AWS_TERRAFORM_REL = Path("deploy/aws/grc-lake-posture-readonly-role.tf")
GCP_TEMPLATE_REL = Path("deploy/gcp/grc-lake-posture-reader.tf")
_GCP_PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_AZURE_SUBSCRIPTION_ID_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_AWS_ROLE_ARN_RE = re.compile(
    r"^arn:(?P<partition>aws(?:-us-gov|-cn)?):iam::(?P<account_id>[0-9]{12}):role/(?P<role_name>[A-Za-z0-9+=,.@_/-]{1,512})$"
)
SESSIONS_FILE = Path("gold") / "connectors" / "cloud_link_sessions.json"
AZURE_DELEGATION_FIELDS = ("tenant_id", "client_id", *AZURE_SECRET_FIELDS)
DELEGATION_FIELDS: dict[str, tuple[str, ...]] = {
    "azure-posture": AZURE_DELEGATION_FIELDS,
    "gcp-posture": (GCP_IMPERSONATION_FIELD,),
}
_LINK_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _sessions_path(lake_dir: str | Path) -> Path:
    return Path(lake_dir) / SESSIONS_FILE


def _load_sessions(lake_dir: str | Path) -> dict[str, Any]:
    path = _sessions_path(lake_dir)
    if not path.is_file():
        return {"sessions": {}}
    try:
        payload = read_json(path)
    except (OSError, json.JSONDecodeError):
        return {"sessions": {}}
    if not isinstance(payload, dict):
        return {"sessions": {}}
    sessions = payload.get("sessions")
    if not isinstance(sessions, dict):
        return {"sessions": {}}
    return {"sessions": sessions}


def _save_sessions(lake_dir: str | Path, payload: dict[str, Any]) -> None:
    path = _sessions_path(lake_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json(path, payload)


def aws_template_bytes() -> bytes:
    """Return the packaged AWS CloudFormation template."""
    return files("security_lakehouse").joinpath("resources/cloud/aws-role.yaml").read_bytes()


def aws_terraform_bytes() -> bytes:
    """Return the packaged AWS Terraform template."""
    return files("security_lakehouse").joinpath("resources/cloud/aws-role.tf").read_bytes()


def gcp_template_bytes() -> bytes:
    """Return the packaged GCP Terraform template."""
    return files("security_lakehouse").joinpath("resources/cloud/gcp-reader.tf").read_bytes()


def _aws_trusted_principal() -> str:
    return str(runtime_env().get("GRC_LAKE_AWS_LINK_PRINCIPAL") or "").strip()


def _azure_link_client_id() -> str:
    return str(runtime_env().get("GRC_LAKE_AZURE_LINK_CLIENT_ID") or "").strip()


def _gcp_wif_member() -> str:
    return str(runtime_env().get("GRC_LAKE_GCP_WIF_MEMBER") or "").strip()


def valid_gcp_project_id(project_id: str) -> bool:
    token = project_id.strip()
    return bool(token and _GCP_PROJECT_ID_RE.fullmatch(token))


def parse_aws_role_arn(role_arn: str) -> tuple[str, str]:
    """Return account ID and normalized ARN for a customer-owned IAM role."""
    normalized = role_arn.strip()
    match = _AWS_ROLE_ARN_RE.fullmatch(normalized)
    if match is None:
        raise ValueError("role_arn must be a valid AWS IAM role ARN")
    return match.group("account_id"), normalized


def gcp_template_url(public_url: str | None) -> str | None:
    base = _public_base(public_url)
    if not base:
        return None
    return f"{base}/api/v1/connectors/gcp-posture/link/template.tf"


def aws_terraform_url(public_url: str | None) -> str | None:
    base = _public_base(public_url)
    if not base:
        return None
    return f"{base}/api/v1/connectors/aws-posture/link/terraform.tf"


def gcp_deploy_command(*, project_id: str = "YOUR_PROJECT_ID", wif_member: str | None = None) -> str:
    """Return a copy-paste Terraform apply command for the GCP reader identity."""
    member = (wif_member or _gcp_wif_member()).strip()
    apply = f'terraform -chdir=deploy/gcp apply -auto-approve -var="project_id={project_id}"'
    if member:
        apply += f' -var="workload_identity_member={member}"'
    return f"terraform -chdir=deploy/gcp init && {apply}"


def aws_deployment_methods() -> list[dict[str, str]]:
    """Return the AWS deploy paths the console can present compactly."""
    return [
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


def aws_cloudshell_command(*, external_id: str, trusted_principal: str, role_name: str) -> str:
    """Return a self-contained CloudShell command with no GRC Lake network dependency."""
    encoded = base64.b64encode(aws_template_bytes()).decode("ascii")
    template_path = "/tmp/grc-lake-posture-readonly-role.yaml"
    return (
        f"printf '%s' '{encoded}' | base64 --decode > {template_path} && "
        "aws cloudformation deploy "
        f"--template-file {template_path} --stack-name GrcLakePostureReadOnly "
        "--capabilities CAPABILITY_NAMED_IAM "
        f"--parameter-overrides TrustedPrincipalArn={trusted_principal} "
        f"ExternalId={external_id} RoleName={role_name} && "
        "aws cloudformation describe-stacks --stack-name GrcLakePostureReadOnly "
        "--query 'Stacks[0].Outputs[?OutputKey==`RoleArn`].OutputValue' --output text"
    )


def aws_scale_strategy() -> dict[str, str]:
    """Describe the supported AWS scale path without making the form taller."""
    return {
        "mode": "stacksets_or_terraform",
        "summary": (
            "Use CloudFormation StackSets or Terraform workspaces to roll out "
            "the same read-only role across AWS accounts."
        ),
        "confirmation": ("Default role name uses account ID confirmation; custom role names use the Role ARN output."),
        "follow_up": ("Bulk account import is the next scale surface after organization rollout is in place."),
    }


def _public_base(public_url: str | None) -> str | None:
    return normalize_public_url(public_url) or normalize_public_url(runtime_env().get("GRC_LAKE_PUBLIC_URL"))


def aws_template_url(public_url: str | None) -> str | None:
    """Return a public HTTPS URL for the AWS template, when ``public_url`` is set."""
    override = str(runtime_env().get("GRC_LAKE_AWS_TEMPLATE_URL") or "").strip()
    if override:
        parsed = urlsplit(override)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            return None
        return override
    base = _public_base(public_url)
    if not base:
        return None
    return f"{base}/api/v1/connectors/aws-posture/link/template.yaml"


def aws_quick_create_url(
    *,
    external_id: str,
    public_url: str | None,
    trusted_principal: str | None = None,
    role_name: str = AWS_ROLE_NAME_DEFAULT,
) -> str | None:
    """Build the AWS console quick-create URL, or ``None`` without a public template URL."""
    template = aws_template_url(public_url)
    if not template:
        return None
    principal = (trusted_principal or _aws_trusted_principal()).strip()
    if not principal:
        return None
    params = {
        "templateURL": template,
        "stackName": "GrcLakePostureReadOnly",
        "param_TrustedPrincipalArn": principal,
        "param_ExternalId": external_id,
        "param_RoleName": role_name,
    }
    query = urlencode(params, quote_via=quote)
    return f"https://console.aws.amazon.com/cloudformation/home#/stacks/quickcreate?{query}"


def azure_consent_url(*, session_id: str, public_url: str | None) -> str | None:
    """Return a Microsoft admin-consent URL when the link app client id is configured."""
    client_id = _azure_link_client_id()
    base = _public_base(public_url)
    if not client_id or not base:
        return None
    redirect_uri = f"{base}/api/v1/connectors/azure-posture/link/callback"
    params = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": session_id,
        }
    )
    return f"https://login.microsoftonline.com/common/adminconsent?{params}"


def normalize_link_session_id(session_id: str) -> str | None:
    """Return a callback-safe cloud-link session id, or ``None`` when invalid."""
    token = session_id.strip()
    if not token or not _LINK_SESSION_ID_RE.fullmatch(token):
        return None
    return token


def azure_callback_redirect(*, session_id: str, public_url: str | None) -> str:
    token = normalize_link_session_id(session_id)
    base = _public_base(public_url)
    if token is None:
        path = "/console/connectors/?connect=azure-posture"
        return f"{base}{path}" if base else path
    path = f"/console/connectors/?connect=azure-posture&link_session={quote(token)}"
    if base:
        return f"{base}{path}"
    return path


def issue_cloud_link_redirect_token(lake_dir: str | Path, *, session_id: str) -> str:
    """Create a server-owned token that the browser can use to complete linking.

    Azure returns the original ``state`` value to the callback. Even after
    validation, some static analyzers conservatively treat that value as
    user-controlled when it is echoed into a redirect URL. The console does not
    need the original state value; it only needs a token that resolves back to
    the pending session. Generate that token here so redirects carry only
    server-minted data.
    """

    token = normalize_link_session_id(session_id)
    if token is None:
        raise KeyError("cloud link session not found")
    store = _load_sessions(lake_dir)
    session = store["sessions"].get(token)
    if not isinstance(session, dict):
        raise KeyError("cloud link session not found")
    redirect_token = secrets.token_urlsafe(18)
    session["redirect_token"] = redirect_token
    session["redirect_token_issued_at"] = utc_iso(datetime.now(UTC))
    store["sessions"][token] = session
    _save_sessions(lake_dir, store)
    return redirect_token


def resolve_cloud_link_session_id(lake_dir: str | Path, session_id: str) -> str | None:
    """Resolve an original session id or browser redirect token to a session id."""

    token = normalize_link_session_id(session_id)
    if token is None:
        return None
    store = _load_sessions(lake_dir)
    if isinstance(store["sessions"].get(token), dict):
        return token
    for original_id, session in store["sessions"].items():
        if isinstance(session, dict) and session.get("redirect_token") == token:
            return str(original_id)
    return None


def link_delegation() -> dict[str, Any]:
    """Whether this caller must supply delegated access, and its secret-ref prefix."""
    if not in_server_mode():
        return {"required": False, "secret_ref_prefix": None}
    tenant = server_tenant_id()
    return {"required": True, "secret_ref_prefix": tenant_secret_prefix(tenant) if tenant else None}


def start_cloud_link(
    lake_dir: str | Path,
    connector_id: str,
    *,
    tenant_id: str,
    public_url: str | None = None,
) -> dict[str, Any]:
    """Create a pending cloud-link session for ``connector_id``."""
    if connector_id not in CLOUD_LINK_CONNECTORS:
        raise ValueError(f"cloud linking is not supported for {connector_id}")
    hosted = in_server_mode()
    if hosted:
        tenant_id = server_tenant_id() or tenant_id
    session_id = secrets.token_urlsafe(18)
    external_id = secrets.token_urlsafe(24)
    trusted_principal = _aws_trusted_principal()
    role_name = AWS_ROLE_NAME_DEFAULT
    session: dict[str, Any] = {
        "session_id": session_id,
        "connector_id": connector_id,
        "tenant_id": tenant_id,
        "status": "pending",
        "created_at": utc_iso(datetime.now(UTC)),
        "external_id": external_id if connector_id == "aws-posture" else None,
        "role_name": role_name if connector_id == "aws-posture" else None,
        "trusted_principal": trusted_principal or None,
        "azure_tenant_id": None,
        "delegation": link_delegation(),
    }
    if connector_id == "aws-posture":
        session["runtime_identity_ready"] = bool(trusted_principal)
        session["cloudshell_command"] = (
            aws_cloudshell_command(
                external_id=external_id,
                trusted_principal=trusted_principal,
                role_name=role_name,
            )
            if trusted_principal
            else None
        )
        session["quick_create_url"] = aws_quick_create_url(
            external_id=external_id,
            public_url=public_url,
            trusted_principal=trusted_principal,
            role_name=role_name,
        )
        session["template_url"] = aws_template_url(public_url)
        session["terraform_url"] = aws_terraform_url(public_url)
        session["manual_template_path"] = str(AWS_TEMPLATE_REL)
        session["manual_terraform_path"] = str(AWS_TERRAFORM_REL)
        session["account_scope"] = "aws_account"
        session["deployment_methods"] = aws_deployment_methods()
        session["scale_strategy"] = aws_scale_strategy()
    if connector_id == "azure-posture":
        # Hosted collection authenticates as the tenant's own app registration,
        # so a server-owned multi-tenant consent app would never be used.
        azure_app_id = "" if hosted else _azure_link_client_id()
        session["azure_app_id"] = azure_app_id or None
        session["runtime_identity_ready"] = bool(azure_app_id)
        session["consent_url"] = None if hosted else azure_consent_url(session_id=session_id, public_url=public_url)
    if connector_id == "gcp-posture":
        wif_member = _gcp_wif_member()
        session["template_url"] = gcp_template_url(public_url)
        session["manual_template_path"] = str(GCP_TEMPLATE_REL)
        session["deploy_command"] = gcp_deploy_command(wif_member=wif_member or None)
        session["workload_identity_member"] = wif_member or None
    store = _load_sessions(lake_dir)
    store["sessions"][session_id] = session
    _save_sessions(lake_dir, store)
    return session


def get_cloud_link_session(lake_dir: str | Path, session_id: str) -> dict[str, Any] | None:
    token = resolve_cloud_link_session_id(lake_dir, session_id)
    if token is None:
        return None
    row = _load_sessions(lake_dir)["sessions"].get(token)
    return row if isinstance(row, dict) else None


def record_azure_consent(
    lake_dir: str | Path,
    *,
    session_id: str,
    azure_tenant_id: str,
    admin_consent: bool,
) -> dict[str, Any]:
    """Persist Azure admin-consent callback metadata on a link session.

    The callback is unauthenticated, so ``azure_tenant_id`` is whatever the
    caller put in the query string. It is recorded for display only and is
    never copied into connector configuration.
    """
    token = normalize_link_session_id(session_id)
    if token is None:
        raise KeyError("cloud link session not found")
    store = _load_sessions(lake_dir)
    session = store["sessions"].get(token)
    if not isinstance(session, dict):
        raise KeyError("cloud link session not found")
    if session.get("connector_id") != "azure-posture":
        raise ValueError("session is not an Azure cloud-link session")
    session["azure_tenant_id"] = azure_tenant_id
    session["admin_consent"] = admin_consent
    session["status"] = "consented" if admin_consent else "consent_denied"
    session["consented_at"] = utc_iso(datetime.now(UTC))
    store["sessions"][token] = session
    _save_sessions(lake_dir, store)
    return session


def complete_cloud_link(
    lake_dir: str | Path,
    connector_id: str,
    *,
    session_id: str,
    actor: str,
    role_arn: str | None = None,
    subscription_id: str | None = None,
    project_id: str | None = None,
    delegation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Finalize a cloud-link session by staging connector credentials.

    ``delegation`` carries the tenant's Azure app registration or GCP
    impersonation target. Hosted mode requires it; locally it is optional and
    validated when present. Secret fields are env-var names, never values.
    """
    token = resolve_cloud_link_session_id(lake_dir, session_id)
    if token is None:
        raise KeyError("cloud link session not found")
    session = get_cloud_link_session(lake_dir, token)
    if session is None:
        raise KeyError("cloud link session not found")
    if session.get("connector_id") != connector_id:
        raise ValueError("session connector mismatch")
    if session.get("status") == "completed":
        raise ValueError("cloud link session is already completed; start a new one to change it")
    credentials: dict[str, Any]
    delegated = _validated_delegation(connector_id, delegation)
    if connector_id == "aws-posture":
        acct, normalized_role_arn = parse_aws_role_arn(role_arn or "")
        credentials = {
            "account_id": acct,
            "external_id": str(session.get("external_id") or ""),
            "role_arn": normalized_role_arn,
        }
    elif connector_id == "azure-posture":
        if not subscription_id or not _AZURE_SUBSCRIPTION_ID_RE.fullmatch(str(subscription_id).strip()):
            raise ValueError("subscription_id must be an Azure subscription id (a GUID)")
        credentials = {"subscription_id": str(subscription_id).strip(), **delegated}
    elif connector_id == "gcp-posture":
        if not project_id or not valid_gcp_project_id(str(project_id)):
            raise ValueError("project_id must be a valid GCP project id")
        credentials = {"project_id": str(project_id).strip(), **delegated}
    else:
        raise ValueError(f"cloud linking is not supported for {connector_id}")
    record = append_config_event(
        lake_dir,
        connector_id=connector_id,
        state="disabled",
        actor=actor,
        credentials=credentials,
        options={},
    )
    store = _load_sessions(lake_dir)
    linked = store["sessions"].get(token)
    if isinstance(linked, dict):
        linked["status"] = "completed"
        linked["completed_at"] = utc_iso(datetime.now(UTC))
        linked["configure_event"] = record.get("occurred_at")
        store["sessions"][token] = linked
        _save_sessions(lake_dir, store)
    return {"session": linked or session, "configure": record}


def _validated_delegation(connector_id: str, delegation: dict[str, Any] | None) -> dict[str, str]:
    """Normalize and validate delegated-access fields with the readers' own rules."""
    allowed = DELEGATION_FIELDS.get(connector_id, ())
    raw = delegation or {}
    unexpected = sorted(set(raw) - set(allowed))
    if unexpected:
        raise ValueError(f"unexpected delegation fields for {connector_id}: {', '.join(unexpected)}")
    fields = {key: str(raw.get(key) or "").strip() for key in allowed}
    fields = {key: value for key, value in fields.items() if value}
    try:
        if connector_id == "azure-posture":
            registration = azure_app_registration(fields, label="Azure posture")
            if registration is None:
                return {}
            tenant_id, client_id, ref_field, ref = registration
            _check_secret_ref(ref, ref_field)
            return {"tenant_id": tenant_id, "client_id": client_id, ref_field: ref}
        if connector_id == "gcp-posture":
            target = gcp_impersonation_target(fields)
            return {GCP_IMPERSONATION_FIELD: target} if target else {}
    except ConnectorConfigError as exc:
        raise ValueError(str(exc)) from exc
    return {}


def _check_secret_ref(ref: str, field: str) -> None:
    if not ENV_NAME_RE.fullmatch(ref):
        raise ValueError(f"{field} must name an environment variable; do not paste the secret itself")
    denial = secret_ref_denial(ref, field=field)
    if denial:
        prefix = link_delegation()["secret_ref_prefix"]
        if prefix and prefix not in denial:
            denial = f"{denial}; use the tenant prefix {prefix}"
        raise ValueError(denial)
