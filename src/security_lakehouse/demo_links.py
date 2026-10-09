"""Shareable demo and account-linking URLs for hosted POC workspaces.

Operators set ``GRC_LAKE_PUBLIC_URL``; this module turns that base URL plus live
connector state into copyable links similar to managed GRC invite and connect flows.
"""

from __future__ import annotations

from typing import Any

from security_lakehouse.connectors import load_connector_catalog
from security_lakehouse.public_url import normalize_public_url

# Connectors most teams link first in a live POC (read-only posture / evidence).
RECOMMENDED_ACCOUNT_CONNECTOR_IDS: tuple[str, ...] = (
    "aws-posture",
    "azure-posture",
    "gcp-posture",
    "snowflake-evidence-lake",
    "github-security",
    "okta-identity",
)


def _console_path(path: str, *, public_url: str | None) -> str:
    """Return an absolute URL when ``public_url`` is set, otherwise a console-relative path."""
    normalized = path if path.startswith("/") else f"/{path}"
    if not public_url:
        return normalized.removeprefix("/console") or normalized
    base = public_url.rstrip("/")
    if normalized.startswith("/console"):
        return f"{base}{normalized}"
    return f"{base}/console{normalized}"


def _account_link_status(connector: dict[str, Any]) -> str:
    """Derive managed-GRC-style account linking state from connector runtime rows."""
    state = str(connector.get("state") or "disabled")
    if state != "enabled":
        return "not_linked"
    latest_sync = connector.get("latest_successful_sync") or connector.get("latest_sync") or {}
    sync_result = str(latest_sync.get("result") or "")
    if sync_result == "ok":
        return "ingesting"
    latest_probe = connector.get("latest_probe") or {}
    if str(latest_probe.get("result") or "") == "ok":
        return "connected"
    if sync_result == "error" or connector.get("last_error"):
        return "error"
    return "enabled"


def build_account_linking(
    ingestion: dict[str, Any],
    *,
    public_url: str | None,
) -> list[dict[str, Any]]:
    """Return recommended account connectors with live link status and deep-link URLs."""
    by_id = {str(row.get("connector_id") or ""): row for row in ingestion.get("connectors") or []}
    catalog = load_connector_catalog()
    out: list[dict[str, Any]] = []
    for connector_id in RECOMMENDED_ACCOUNT_CONNECTOR_IDS:
        base = catalog.get(connector_id) or {}
        label = str(base.get("vendor") or base.get("name") or connector_id)
        setup_hint = str(base.get("setup_hint") or "")
        row = by_id.get(connector_id) or {}
        status = _account_link_status(row)
        latest_success = row.get("latest_successful_sync") or row.get("latest_sync") or {}
        out.append(
            {
                "connector_id": connector_id,
                "label": label,
                "setup_hint": setup_hint,
                "status": status,
                "enabled": str(row.get("state") or "") == "enabled",
                "evidence_count": int(latest_success.get("evidence_count") or 0),
                "last_sync_at": latest_success.get("occurred_at"),
                "last_sync_result": latest_success.get("result"),
                "connect_url": _console_path(f"/connectors/?connect={connector_id}", public_url=public_url),
            }
        )
    return out


def build_share_links(
    *,
    public_url: str | None,
    sso_configured: bool,
    require_auth: bool,
    active_share_count: int,
    login_path: str = "/api/v1/auth/login",
) -> list[dict[str, Any]]:
    """Return copyable workspace links for operators and evaluators."""
    public_url = normalize_public_url(public_url)
    links: list[dict[str, Any]] = []
    if public_url:
        links.append(
            {
                "kind": "workspace",
                "label": "Team workspace",
                "description": "Sign in and review live posture, controls, and evidence.",
                "url": _console_path("/dashboard/", public_url=public_url),
                "audience": "internal",
            }
        )
        links.append(
            {
                "kind": "launch",
                "label": "Launch checklist",
                "description": "POC readiness gates, account linking, and share prep.",
                "url": _console_path("/poc/", public_url=public_url),
                "audience": "operator",
            }
        )
        links.append(
            {
                "kind": "connect",
                "label": "Connect accounts",
                "description": "Link cloud, identity, and evidence-lake sources with read-only scope.",
                "url": _console_path("/connectors/", public_url=public_url),
                "audience": "operator",
            }
        )
        if sso_configured:
            links.append(
                {
                    "kind": "login",
                    "label": "Sign-in link",
                    "description": "Browser SSO entry for evaluators and workspace members.",
                    "url": f"{public_url.rstrip('/')}{login_path}",
                    "audience": "evaluator",
                }
            )
        elif require_auth:
            links.append(
                {
                    "kind": "login",
                    "label": "Sign-in page",
                    "description": "Console sign-in — SSO when configured, or API key session.",
                    "url": _console_path("/login/", public_url=public_url),
                    "audience": "evaluator",
                }
            )
        links.append(
            {
                "kind": "demo",
                "label": "Demo landing",
                "description": "Evaluator-facing overview of ingestion, linking, and trust sharing.",
                "url": _console_path("/demo/", public_url=public_url),
                "audience": "evaluator",
            }
        )
        links.append(
            {
                "kind": "trust_center",
                "label": "Trust center",
                "description": "Issue scoped reviewer links without exposing raw evidence.",
                "url": _console_path("/trust-center/", public_url=public_url),
                "audience": "operator",
            }
        )
    else:
        links.append(
            {
                "kind": "workspace",
                "label": "Local workspace",
                "description": "Set GRC_LAKE_PUBLIC_URL to generate invite links for a hosted demo.",
                "url": "/dashboard/",
                "audience": "operator",
            }
        )

    if active_share_count > 0 and public_url:
        links.append(
            {
                "kind": "trust_share_active",
                "label": "Active trust shares",
                "description": f"{active_share_count} scoped reviewer link(s) issued. Tokens are shown once at creation.",
                "url": _console_path("/trust-center/", public_url=public_url),
                "audience": "evaluator",
            }
        )
    return links


def build_demo_kit(
    *,
    public_url: str | None,
    sso_configured: bool,
    require_auth: bool,
    ingestion: dict[str, Any],
    active_share_count: int,
    shareable: bool,
    login_path: str = "/api/v1/auth/login",
) -> dict[str, Any]:
    """Bundle share URLs and account-linking status for the hosted demo experience."""
    public_url = normalize_public_url(public_url)
    account_linking = build_account_linking(ingestion, public_url=public_url)
    linked = [row for row in account_linking if row["status"] in {"connected", "ingesting"}]
    ingesting = [row for row in account_linking if row["status"] == "ingesting"]
    return {
        "shareable": shareable,
        "public_url": public_url,
        "share_links": build_share_links(
            public_url=public_url,
            sso_configured=sso_configured,
            require_auth=require_auth,
            active_share_count=active_share_count,
            login_path=login_path,
        ),
        "account_linking": account_linking,
        "account_linking_summary": {
            "recommended": len(account_linking),
            "connected_or_ingesting": len(linked),
            "live_ingestion": len(ingesting),
        },
        "ingestion_proof": ingestion.get("proof"),
    }
