"""Explicit, tenant-delegated cloud access for hosted server mode.

Locally the operator's ambient identity (SSO profile, instance role, ADC,
in-cluster service account) is the intended credential. In hosted server mode a
tenant names the target account or project, so collecting with the server's own
identity would let one tenant read whatever that identity can reach. There:

* AWS readers assume the tenant's role and must present its external id
  (confused-deputy protection); ambient credentials are refused.
* GCP readers impersonate a tenant-named service account from the server's
  ADC; the server's own ADC is never used against the target project directly.

Local/CLI mode is unchanged.
"""

from __future__ import annotations

import re
from typing import Any

from security_lakehouse.connector_errors import ConnectorConfigError
from security_lakehouse.execution_mode import in_server_mode

GCP_IMPERSONATION_FIELD = "impersonate_service_account"
GCP_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
GCP_TOKEN_LIFETIME_SECONDS = 3600
_SERVICE_ACCOUNT_EMAIL = re.compile(
    r"^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$"
)


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
    target = str(credentials.get(GCP_IMPERSONATION_FIELD) or "").strip()
    if not target:
        if in_server_mode():
            raise ConnectorConfigError(
                f"GCP readers in hosted mode require {GCP_IMPERSONATION_FIELD}: a service account in the "
                "customer project that grants the TrustOps identity the Service Account Token Creator role"
            )
        return None
    if not _SERVICE_ACCOUNT_EMAIL.fullmatch(target):
        raise ConnectorConfigError(
            f"{GCP_IMPERSONATION_FIELD} must be a service account email (…iam.gserviceaccount.com)"
        )
    try:
        import google.auth  # noqa: PLC0415
        from google.auth import impersonated_credentials  # noqa: PLC0415
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
    "GCP_IMPERSONATION_FIELD",
    "gcp_credentials",
    "require_aws_delegation",
    "server_env_override",
]
