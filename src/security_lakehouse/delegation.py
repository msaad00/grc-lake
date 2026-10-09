"""Explicit, tenant-delegated cloud access for hosted server mode.

Locally the operator's ambient identity (SSO profile, instance role, ADC,
in-cluster service account) is the intended credential. In hosted server mode a
tenant names the target account or project, so collecting with the server's own
identity would let one tenant read whatever that identity can reach. There:

* AWS readers assume the tenant's role and must present its external id
  (confused-deputy protection); ambient credentials are refused.
* GCP readers impersonate a tenant-named service account from the server's
  ADC; the server's own ADC is never used against the target project directly.
* Azure readers authenticate as the tenant's own Entra app registration
  (``tenant_id`` + ``client_id`` plus a client secret, a certificate, or a
  federated token file named through the tenant's secret-reference prefix);
  ``DefaultAzureCredential`` and the ``az`` CLI login are refused.

Local/CLI mode is unchanged.
"""

from __future__ import annotations

import re
from typing import Any

from security_lakehouse.connector_errors import ConnectorConfigError
from security_lakehouse.execution_mode import in_server_mode
from security_lakehouse.runtime_environment import runtime_env
from security_lakehouse.secret_refs import resolve_secret_ref

GCP_IMPERSONATION_FIELD = "impersonate_service_account"
GCP_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
GCP_TOKEN_LIFETIME_SECONDS = 3600
_SERVICE_ACCOUNT_EMAIL = re.compile(
    r"^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$"
)


AZURE_SECRET_FIELDS = ("client_secret_ref", "client_certificate_ref", "federated_token_file_ref")
# Entra tenant ids are GUIDs or verified domain names; azure-identity accepts
# the same character set when it builds the authority URL.
_AZURE_TENANT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
_AZURE_CLIENT_ID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")


def azure_credential(credentials: dict[str, Any], env: dict[str, str], *, label: str) -> Any:
    """The tenant's own Entra app credential, or ``None`` for the local ambient identity.

    ``credentials`` carries ``tenant_id`` and ``client_id`` of an app
    registration in the customer's Entra tenant and exactly one of
    :data:`AZURE_SECRET_FIELDS`, each an env-var reference resolved through
    :func:`security_lakehouse.secret_refs.resolve_secret_ref`:

    * ``client_secret_ref``: the app's client secret;
    * ``client_certificate_ref``: a PEM certificate with its private key
      (inline, or mounted via ``<NAME>_FILE``);
    * ``federated_token_file_ref``: a path to a federated (workload identity)
      token file the app's federated credential trusts.

    Locally, with none of these set, returns ``None`` so callers keep
    ``DefaultAzureCredential``. In server mode that is refused.
    """
    env = runtime_env(env)
    delegated = azure_app_registration(credentials, label=label)
    if delegated is None:
        return None
    tenant_id, client_id, field, ref = delegated
    value = resolve_secret_ref(ref, env, field=field, file_first=field != "federated_token_file_ref")
    if not value:
        raise ConnectorConfigError(f"{label}: the variable named by {field} is not set")
    try:
        import azure.identity as azure_identity
    except ImportError as exc:  # pragma: no cover - optional extra
        raise ConnectorConfigError(f"{label} requires azure-identity; install the cloud extra") from exc
    if field == "client_secret_ref":
        return azure_identity.ClientSecretCredential(tenant_id, client_id, value)
    if field == "client_certificate_ref":
        return azure_identity.CertificateCredential(tenant_id, client_id, certificate_data=value.encode("utf-8"))
    return azure_identity.WorkloadIdentityCredential(tenant_id=tenant_id, client_id=client_id, token_file_path=value)


def azure_app_registration(credentials: dict[str, Any], *, label: str) -> tuple[str, str, str, str] | None:
    """Validate the Entra app registration fields without resolving any secret.

    Returns ``(tenant_id, client_id, ref_field, ref_name)``, or ``None`` locally
    when no app registration is configured. Raises
    :class:`ConnectorConfigError` for an incomplete or ambiguous registration,
    and in server mode when none is configured.
    """
    tenant_id = str(credentials.get("tenant_id") or "").strip()
    client_id = str(credentials.get("client_id") or "").strip()
    refs = {field: str(credentials.get(field) or "").strip() for field in AZURE_SECRET_FIELDS}
    configured = [field for field, value in refs.items() if value]
    if not client_id and not configured:
        if in_server_mode():
            raise ConnectorConfigError(
                f"{label} in hosted mode requires tenant_id, client_id, and one of "
                f"{', '.join(AZURE_SECRET_FIELDS)} for an app registration in the customer's Entra tenant; "
                "the server never collects with its own Azure identity"
            )
        return None
    if not _AZURE_TENANT_ID.fullmatch(tenant_id):
        raise ConnectorConfigError(f"{label} requires tenant_id: the customer's Entra tenant id or domain")
    if not _AZURE_CLIENT_ID.fullmatch(client_id):
        raise ConnectorConfigError(f"{label} requires client_id: the application (client) id of the app registration")
    if len(configured) != 1:
        raise ConnectorConfigError(f"{label} requires exactly one of {', '.join(AZURE_SECRET_FIELDS)}")
    field = configured[0]
    return tenant_id, client_id, field, refs[field]


def gcp_impersonation_target(credentials: dict[str, Any]) -> str | None:
    """The validated service account to impersonate, or ``None`` locally when unset."""
    target = str(credentials.get(GCP_IMPERSONATION_FIELD) or "").strip()
    if not target:
        if in_server_mode():
            raise ConnectorConfigError(
                f"GCP readers in hosted mode require {GCP_IMPERSONATION_FIELD}: a service account in the "
                "customer project that grants the GRC Lake identity the Service Account Token Creator role"
            )
        return None
    if not _SERVICE_ACCOUNT_EMAIL.fullmatch(target):
        raise ConnectorConfigError(
            f"{GCP_IMPERSONATION_FIELD} must be a service account email (…iam.gserviceaccount.com)"
        )
    return target


def require_aws_delegation(role_arn: str | None, external_id: str | None, *, label: str) -> None:
    """In server mode, refuse any AWS access that is not role + external id."""
    if not in_server_mode():
        return
    if not (role_arn or "").strip() or not (external_id or "").strip():
        raise ConnectorConfigError(
            f"{label} in hosted mode requires role_arn and external_id for the customer's read-only role; "
            "the server never collects with its own AWS identity"
        )


def server_env_override(value: str | None) -> str | None:
    """An operator env override that must not apply to tenant connectors in server mode."""
    return None if in_server_mode() else value


def gcp_credentials(credentials: dict[str, Any]) -> Any:
    """Credentials for a GCP reader: impersonated when configured, required in server mode.

    Returns ``None`` locally when no impersonation target is set, meaning the
    client libraries use Application Default Credentials as before.
    """
    target = gcp_impersonation_target(credentials)
    if target is None:
        return None
    try:
        import google.auth
        from google.auth import impersonated_credentials
    except ImportError as exc:  # pragma: no cover - optional extra
        raise ConnectorConfigError("GCP impersonation requires google-auth; install the cloud extra") from exc
    source, _project = google.auth.default(scopes=GCP_SCOPES)
    return impersonated_credentials.Credentials(
        source_credentials=source,
        target_principal=target,
        target_scopes=GCP_SCOPES,
        lifetime=GCP_TOKEN_LIFETIME_SECONDS,
    )


__all__ = [
    "AZURE_SECRET_FIELDS",
    "GCP_IMPERSONATION_FIELD",
    "azure_app_registration",
    "azure_credential",
    "gcp_credentials",
    "gcp_impersonation_target",
    "require_aws_delegation",
    "server_env_override",
]
