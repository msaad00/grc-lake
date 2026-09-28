"""Data sensitivity and role visibility policy.

This module is deliberately small and deterministic. TrustOps can use agents or
LLMs around the product, but data visibility must stay ordinary code that is
easy to test and audit.
"""

from __future__ import annotations

from typing import Any

SENSITIVITY_LEVELS = ("public", "internal", "confidential", "restricted", "secret")
SENSITIVITY_RANK = {level: index for index, level in enumerate(SENSITIVITY_LEVELS)}

ROLE_SENSITIVITY_CEILING: dict[str, str] = {
    "admin": "restricted",
    "security_admin": "restricted",
    "compliance_reviewer": "confidential",
    "contributor": "confidential",
    "read_only": "confidential",
    "auditor": "internal",
    "public_share": "public",
}

AUDITOR_REDACTED_FIELDS = frozenset({"owner", "asset_owner", "actor", "assignee", "note", "credentials"})


def normalize_sensitivity(value: object, *, default: str = "internal") -> str:
    """Return a known sensitivity label."""
    label = str(value or default).strip().lower()
    return label if label in SENSITIVITY_RANK else default


def sensitivity_allowed(*, role: str, sensitivity: object, ceiling: str | None = None) -> bool:
    """Whether ``role`` can see a value marked with ``sensitivity``."""
    allowed = normalize_sensitivity(ceiling or ROLE_SENSITIVITY_CEILING.get(role, "internal"))
    required = normalize_sensitivity(sensitivity)
    return SENSITIVITY_RANK[required] <= SENSITIVITY_RANK[allowed]


def redact_payload(payload: object, *, role: str, ceiling: str | None = None) -> object:
    """Apply role and sensitivity redaction to a JSON-like payload.

    Explicit ``sensitivity``/``data_sensitivity`` fields can hide an entire
    object from roles below that clearance. Auditor/public-share roles also get
    owner-grade fields redacted recursively.
    """
    if isinstance(payload, list):
        return [redact_payload(item, role=role, ceiling=ceiling) for item in payload]
    if not isinstance(payload, dict):
        return payload

    sensitivity = payload.get("sensitivity", payload.get("data_sensitivity"))
    if sensitivity is not None and not sensitivity_allowed(role=role, sensitivity=sensitivity, ceiling=ceiling):
        return {
            "sensitivity": normalize_sensitivity(sensitivity),
            "redacted": True,
            "redaction_reason": "sensitivity exceeds role visibility",
        }

    redact_owner_fields = role in {"auditor", "public_share"}
    out: dict[str, Any] = {}
    for key, value in payload.items():
        if redact_owner_fields and key in AUDITOR_REDACTED_FIELDS:
            out[key] = "[redacted]"
        else:
            out[key] = redact_payload(value, role=role, ceiling=ceiling)
    return out
