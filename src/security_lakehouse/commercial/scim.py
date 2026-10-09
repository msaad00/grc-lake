"""SCIM 2.0 settings for commercial hosted tenants.

Provisioning lives in :mod:`security_lakehouse.commercial.scim_provision` and
the routes in :mod:`security_lakehouse.server_routes.routers.scim`; both return
501 unless the commercial hosted build enables SCIM.
"""

from __future__ import annotations

from typing import Any

from security_lakehouse.commercial.email import commercial_hosted_enabled
from security_lakehouse.runtime_environment import runtime_env


def scim_enabled() -> bool:
    return commercial_hosted_enabled() and runtime_env().get("GRC_LAKE_SCIM_ENABLED", "").lower() in {
        "1",
        "true",
        "yes",
    }


def scim_config() -> dict[str, Any]:
    """Return non-secret SCIM settings for operator dashboards."""
    return {
        "enabled": scim_enabled(),
        "base_path": "/api/v1/scim/v2",
        "supported": scim_enabled(),
        "note": (
            "SCIM uses per-tenant bearer tokens issued at /api/v1/platform/scim/tokens (SHA-256 hashed at rest). "
            "OSS/self-hosted returns 501 until GRC_LAKE_COMMERCIAL_HOSTED=1 and GRC_LAKE_SCIM_ENABLED=1."
        ),
    }


def scim_not_implemented_detail() -> str:
    return (
        "SCIM provisioning is a commercial hosted feature; enable GRC_LAKE_COMMERCIAL_HOSTED and GRC_LAKE_SCIM_ENABLED"
    )


__all__ = ["scim_config", "scim_enabled", "scim_not_implemented_detail"]
