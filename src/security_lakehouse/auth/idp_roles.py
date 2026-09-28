"""Map IdP group/role claims to TrustOps product roles."""

from __future__ import annotations

import json
import os
from typing import Any

from security_lakehouse.db.models import USER_ROLES

ROLE_RANK: dict[str, int] = {
    "auditor": 1,
    "read_only": 2,
    "compliance_reviewer": 3,
    "contributor": 4,
    "security_admin": 5,
    "admin": 6,
}


def load_role_map(env_var: str) -> dict[str, str]:
    """Parse ``TRUSTOPS_*_ROLE_MAP`` JSON: ``{\"IdP-Group\": \"admin\"}``."""
    raw = os.environ.get(env_var, "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{env_var} must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{env_var} must be a JSON object")
    out: dict[str, str] = {}
    for key, value in parsed.items():
        role = str(value).strip()
        if role not in USER_ROLES:
            raise ValueError(f"{env_var} maps {key!r} to invalid role {role!r}")
        out[str(key).strip()] = role
    return out


def extract_claim_values(userinfo: dict[str, Any], claim_name: str) -> list[str]:
    """Normalize IdP claim to a list of group/role strings."""
    if not claim_name:
        return []
    value = userinfo.get(claim_name)
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


def resolve_role_from_claims(
    claim_values: list[str],
    *,
    role_map: dict[str, str],
    default_role: str,
) -> str:
    """Pick the highest-privilege TrustOps role matched by IdP groups."""
    if default_role not in USER_ROLES:
        default_role = "read_only"
    best = default_role
    best_rank = ROLE_RANK.get(best, 0)
    for claim in claim_values:
        mapped = role_map.get(claim)
        if mapped is None:
            continue
        rank = ROLE_RANK.get(mapped, 0)
        if rank > best_rank:
            best = mapped
            best_rank = rank
    return best


def sync_role_on_login_enabled() -> bool:
    return os.environ.get("TRUSTOPS_IDP_SYNC_ROLE_ON_LOGIN", "").lower() in {"1", "true", "yes"}
