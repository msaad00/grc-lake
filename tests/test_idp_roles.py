"""IdP group → TrustOps role mapping."""

from __future__ import annotations

import pytest

from security_lakehouse.auth.idp_roles import (
    extract_claim_values,
    resolve_role_from_claims,
)


def test_extract_claim_values_normalizes_shapes() -> None:
    assert extract_claim_values({"groups": ["Admins", "Staff"]}, "groups") == ["Admins", "Staff"]
    assert extract_claim_values({"roles": "admin"}, "roles") == ["admin"]
    assert extract_claim_values({}, "groups") == []


def test_resolve_role_picks_highest_privilege() -> None:
    role = resolve_role_from_claims(
        ["Staff", "TrustOps-Admins"],
        role_map={"Staff": "read_only", "TrustOps-Admins": "admin"},
        default_role="read_only",
    )
    assert role == "admin"


def test_resolve_role_falls_back_to_default() -> None:
    role = resolve_role_from_claims(
        ["Unknown-Group"],
        role_map={"Admins": "admin"},
        default_role="contributor",
    )
    assert role == "contributor"


def test_load_role_map_rejects_invalid_role(monkeypatch: pytest.MonkeyPatch) -> None:
    from security_lakehouse.auth.idp_roles import load_role_map

    monkeypatch.setenv("TRUSTOPS_OIDC_ROLE_MAP", '{"Admins": "superuser"}')
    with pytest.raises(ValueError, match="invalid role"):
        load_role_map("TRUSTOPS_OIDC_ROLE_MAP")
