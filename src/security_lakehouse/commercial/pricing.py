"""Published hosted pricing tiers for managed SaaS (commercial hosted only)."""

from __future__ import annotations

from typing import Any

from security_lakehouse.commercial.email import commercial_hosted_enabled

TIER_IDS = ("starter", "team", "business", "enterprise")

_TIERS: dict[str, dict[str, Any]] = {
    "starter": {
        "id": "starter",
        "name": "Starter",
        "annual_usd": 4_800,
        "annual_usd_label": "$4,800",
        "tagline": "Evaluator workspace and small-team POC",
        "limits": {
            "max_users": 5,
            "max_api_keys": 10,
            "max_invites_pending": 10,
            "max_connectors": 2,
            "scim": False,
        },
        "includes": [
            "Hosted workspace URL",
            "OIDC / SAML SSO",
            "2 live connectors",
            "Trust-center shares",
            "Community support",
        ],
    },
    "team": {
        "id": "team",
        "name": "Team",
        "annual_usd": 12_000,
        "annual_usd_label": "$12,000",
        "tagline": "Production pilot for one framework program",
        "limits": {
            "max_users": 25,
            "max_api_keys": 50,
            "max_invites_pending": 50,
            "max_connectors": 10,
            "scim": False,
        },
        "includes": [
            "Everything in Starter",
            "10 connectors + scheduler",
            "Workflow automation",
            "Agent harness + MCP",
            "Email support (business hours)",
        ],
    },
    "business": {
        "id": "business",
        "name": "Business",
        "annual_usd": 28_000,
        "annual_usd_label": "$28,000",
        "tagline": "Multi-framework GRC with SCIM lifecycle",
        "limits": {
            "max_users": 100,
            "max_api_keys": 200,
            "max_invites_pending": 200,
            "max_connectors": 50,
            "scim": True,
        },
        "includes": [
            "Everything in Team",
            "SCIM 2.0 provisioning",
            "Vendor risk + policy library",
            "HA read-replica guidance",
            "Priority support",
        ],
    },
    "enterprise": {
        "id": "enterprise",
        "name": "Enterprise",
        "annual_usd": None,
        "annual_usd_label": "Custom",
        "tagline": "Dedicated tenant, custom SLAs, and air-gap options",
        "limits": {
            "max_users": 10_000,
            "max_api_keys": 10_000,
            "max_invites_pending": 10_000,
            "max_connectors": 10_000,
            "scim": True,
        },
        "includes": [
            "Dedicated or isolated cluster",
            "Custom framework packs",
            "Customer success + onboarding",
            "Annual price targets ~⅓–½ managed GRC platform TCO",
        ],
    },
}


def list_pricing_tiers() -> list[dict[str, Any]]:
    """Return published tiers in ascending price order."""
    ordered = [tier for tier_id in TIER_IDS if (tier := _TIERS.get(tier_id))]
    return [
        {
            "id": tier["id"],
            "name": tier["name"],
            "annual_usd": tier["annual_usd"],
            "annual_usd_label": tier["annual_usd_label"],
            "tagline": tier["tagline"],
            "limits": dict(tier["limits"]),
            "includes": list(tier["includes"]),
        }
        for tier in ordered
    ]


def get_tier(tier_id: str) -> dict[str, Any] | None:
    tier = _TIERS.get(tier_id.strip().lower())
    if tier is None:
        return None
    return {
        "id": tier["id"],
        "name": tier["name"],
        "annual_usd": tier["annual_usd"],
        "annual_usd_label": tier["annual_usd_label"],
        "tagline": tier["tagline"],
        "limits": dict(tier["limits"]),
        "includes": list(tier["includes"]),
    }


def tier_limits(tier_id: str) -> dict[str, Any]:
    tier = get_tier(tier_id) or get_tier("starter")
    assert tier is not None
    return dict(tier["limits"])


def pricing_payload() -> dict[str, Any]:
    if not commercial_hosted_enabled():
        return {
            "currency": "USD",
            "billing_period": "annual",
            "note": (
                "GRC Lake is open source — run locally or self-host in your cloud. "
                "Managed cloud pricing is not published in the OSS console."
            ),
            "tiers": [],
        }
    return {
        "currency": "USD",
        "billing_period": "annual",
        "note": (
            "Published list prices for managed hosted GRC Lake workspaces. "
            "Contact sales for enterprise quotes and multi-year discounts."
        ),
        "tiers": list_pricing_tiers(),
    }


__all__ = ["TIER_IDS", "get_tier", "list_pricing_tiers", "pricing_payload", "tier_limits"]
