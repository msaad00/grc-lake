"""Self-serve tenant signup for commercial hosted workspaces."""

from __future__ import annotations

import hmac
import re
from typing import Any

from sqlalchemy.orm import Session

from security_lakehouse.commercial.email import commercial_hosted_enabled
from security_lakehouse.commercial.pricing import TIER_IDS, get_tier
from security_lakehouse.db import repository
from security_lakehouse.runtime_environment import runtime_env

_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def self_serve_signup_enabled() -> bool:
    return commercial_hosted_enabled() and runtime_env().get("GRC_LAKE_SELF_SERVE_SIGNUP", "").lower() in {
        "1",
        "true",
        "yes",
    }


def signup_secret_configured() -> bool:
    return bool(runtime_env().get("GRC_LAKE_SIGNUP_SECRET", "").strip())


def open_signup_allowed() -> bool:
    return runtime_env().get("GRC_LAKE_ALLOW_OPEN_SIGNUP", "").strip().lower() in {"1", "true", "yes"}


def verify_signup_secret(provided: str | None) -> bool:
    """Check the signup secret; with none configured, signup is closed unless explicitly opened."""
    expected = runtime_env().get("GRC_LAKE_SIGNUP_SECRET", "").strip()
    if not expected:
        return open_signup_allowed()
    return hmac.compare_digest((provided or "").strip().encode("utf-8"), expected.encode("utf-8"))


def normalize_slug(raw: str) -> str:
    slug = raw.strip().lower().replace("_", "-")
    if not slug or not _SLUG_RE.match(slug):
        raise ValueError("org_slug must be 2-63 lowercase letters, digits, or hyphens")
    return slug


def create_workspace(
    session: Session,
    *,
    org_slug: str,
    org_name: str,
    admin_email: str,
    admin_name: str = "",
    plan_tier: str = "starter",
) -> dict[str, Any]:
    """Create tenant + first admin user for self-serve signup."""
    if not self_serve_signup_enabled():
        raise ValueError("self-serve signup requires GRC_LAKE_COMMERCIAL_HOSTED=1 and GRC_LAKE_SELF_SERVE_SIGNUP=1")
    slug = normalize_slug(org_slug)
    tier = plan_tier.strip().lower()
    if tier not in TIER_IDS:
        raise ValueError(f"plan_tier must be one of {list(TIER_IDS)}, got {plan_tier!r}")
    if get_tier(tier) is None:
        raise ValueError(f"unknown plan_tier {plan_tier!r}")
    if repository.get_tenant_by_slug(session, slug=slug) is not None:
        raise ValueError(f"workspace slug {slug!r} is already taken")
    email = admin_email.strip().lower()
    if not email or "@" not in email:
        raise ValueError("admin_email is required")

    tenant = repository.create_tenant(session, slug=slug, name=org_name.strip() or slug)
    tenant.plan_tier = tier
    user = repository.create_user(
        session,
        tenant_id=tenant.id,
        email=email,
        display_name=admin_name.strip() or email.split("@", 1)[0],
        role="admin",
    )
    session.flush()
    return {
        "tenant_id": tenant.id,
        "org_slug": tenant.slug,
        "org_name": tenant.name,
        "plan_tier": tier,
        "admin_user_id": user.id,
        "admin_email": user.email,
        "next_steps": [
            "Configure OIDC/SAML for browser login",
            "Create an API key for automation",
            "Connect your first read-only source",
        ],
    }


__all__ = [
    "create_workspace",
    "normalize_slug",
    "open_signup_allowed",
    "self_serve_signup_enabled",
    "signup_secret_configured",
    "verify_signup_secret",
]
