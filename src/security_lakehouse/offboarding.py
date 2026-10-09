"""Offboarding check: HR terminations joined to identity-provider accounts.

After any HRIS or identity-provider sync, the runner rebuilds one derived
evidence row per terminated employee by joining ``hris.personnel.employment``
rows (any HR vendor) to IdP user rows (Okta, Google Workspace) on the
lower-cased work email. The rows are written as a snapshot under
:data:`OFFBOARDING_CONNECTOR_ID`, so they flow through the same raw → silver →
gold path as connector evidence and a fixed account clears on the next sync.

Outcomes per terminated employee:

* ``active_after_termination`` — an account can still authenticate more than
  the grace period after termination: open, high.
* ``within_grace_period`` — still active, but inside the grace period: observed.
* ``deprovisioned`` — every matched account is disabled: pass.
* ``no_idp_account_matched`` — no IdP account shares the work email: observed,
  never a pass, because absence of a match proves nothing.

No rows are produced unless both HR and IdP evidence are present.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from typing import Any

from security_lakehouse.hris import PERSONNEL_SENSITIVITY, parse_hr_date
from security_lakehouse.models import utc_iso
from security_lakehouse.runtime_environment import runtime_env

OFFBOARDING_CONNECTOR_ID = "hris-idp-offboarding"
OFFBOARDING_SOURCE = "trustops-correlation"
HRIS_EVENT_TYPE = "hris.personnel.employment"
GRACE_DAYS_ENV = "GRC_LAKE_OFFBOARDING_GRACE_DAYS"
DEFAULT_GRACE_DAYS = 1
MAX_GRACE_DAYS = 365

# event_type -> attribute holding the account's email/login.
IDP_ACCOUNT_EMAIL_FIELDS = {
    "okta.identity.user_access": "login",
    "google_workspace.identity.user_access": "primary_email",
}

# Controls verified to exist in controls/catalog.json; every rule here fails on
# an open violation.
OFFBOARDING_CONTROLS = [
    "SOC2-CC6.2",
    "FEDRAMP-PS-4",
    "FEDRAMP-AC-2.3",
    "ISO27001-A.5.18",
    "ISO27001-A.6.5",
    "CMMC-3.9.2",
]


def is_offboarding_input(row: Mapping[str, Any]) -> bool:
    event_type = str(row.get("event_type") or "")
    return event_type == HRIS_EVENT_TYPE or event_type in IDP_ACCOUNT_EMAIL_FIELDS


def grace_days_from_env(env: Mapping[str, str]) -> int:
    env = runtime_env(env)
    try:
        value = int(env.get(GRACE_DAYS_ENV, DEFAULT_GRACE_DAYS))
    except ValueError:
        return DEFAULT_GRACE_DAYS
    return value if 0 <= value <= MAX_GRACE_DAYS else DEFAULT_GRACE_DAYS


def correlate_offboarding(
    raw_rows: Iterable[Mapping[str, Any]],
    *,
    as_of: date,
    collected_at: datetime,
    grace_days: int = DEFAULT_GRACE_DAYS,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    hr_rows: list[Mapping[str, Any]] = []
    accounts: dict[str, list[dict[str, Any]]] = {}
    for row in raw_rows:
        event_type = str(row.get("event_type") or "")
        attributes = _mapping(row.get("attributes"))
        if event_type == HRIS_EVENT_TYPE:
            hr_rows.append(row)
        elif event_type in IDP_ACCOUNT_EMAIL_FIELDS:
            email = _email(attributes.get(IDP_ACCOUNT_EMAIL_FIELDS[event_type]))
            if email:
                entity = _mapping(row.get("entity"))
                accounts.setdefault(email, []).append(
                    {
                        "source": str(row.get("source") or ""),
                        "account_id": str(entity.get("asset_id") or ""),
                        "can_authenticate": attributes.get("can_authenticate") is True,
                    }
                )
    if not hr_rows or not accounts:
        return []

    out: list[dict[str, Any]] = []
    for row in hr_rows:
        attributes = _mapping(row.get("attributes"))
        terminated_on = parse_hr_date(attributes.get("termination_date"))
        if terminated_on is None or terminated_on > as_of:
            continue
        email = _email(attributes.get("work_email"))
        matched = accounts.get(email, []) if email else []
        active = [{"source": a["source"], "account_id": a["account_id"]} for a in matched if a["can_authenticate"]]
        days = (as_of - terminated_on).days
        if not matched:
            status, severity, outcome = "observed", "low", "no_idp_account_matched"
        elif not active:
            status, severity, outcome = "pass", "info", "deprovisioned"
        elif days > grace_days:
            status, severity, outcome = "open", "high", "active_after_termination"
        else:
            status, severity, outcome = "observed", "medium", "within_grace_period"
        out.append(
            _event(
                row,
                attributes,
                status=status,
                severity=severity,
                outcome=outcome,
                days=days,
                grace_days=grace_days,
                matched=matched,
                active=active,
                collected_at=collected_at,
                tenant_id=tenant_id,
            )
        )
    return out


def _event(
    hr_row: Mapping[str, Any],
    attributes: Mapping[str, Any],
    *,
    status: str,
    severity: str,
    outcome: str,
    days: int,
    grace_days: int,
    matched: list[dict[str, Any]],
    active: list[dict[str, str]],
    collected_at: datetime,
    tenant_id: str,
) -> dict[str, Any]:
    entity = _mapping(hr_row.get("entity"))
    asset_id = str(entity.get("asset_id") or "")
    stable = re.sub(r"[^a-z0-9_.:-]+", "-", f"offboarding:{asset_id}".lower()).strip("-")[:96]
    return {
        "event_id": f"correlation-{stable}",
        "tenant_id": tenant_id,
        "workspace_id": "default",
        "event_time": utc_iso(collected_at),
        "source": OFFBOARDING_SOURCE,
        "event_type": "correlation.personnel.offboarding",
        "entity": {
            "asset_id": asset_id,
            "asset_type": "hris_employee",
            "asset_owner": str(entity.get("asset_owner") or ""),
            "environment": "prod",
            "org": str(entity.get("org") or ""),
        },
        "severity": severity,
        "status": status,
        "controls": OFFBOARDING_CONTROLS,
        "evidence": {
            "evidence_id": f"ev-{stable}",
            "evidence_ref": str(_mapping(hr_row.get("evidence")).get("evidence_ref") or asset_id),
            "evidence_collected_at": utc_iso(collected_at),
        },
        "attributes": {
            "employee_id": attributes.get("employee_id"),
            "hr_source": hr_row.get("source"),
            "work_email": attributes.get("work_email"),
            "termination_date": attributes.get("termination_date"),
            "days_since_termination": days,
            "grace_days": grace_days,
            "outcome": outcome,
            "matched_account_count": len(matched),
            "active_accounts": active,
            "data_sensitivity": PERSONNEL_SENSITIVITY,
        },
    }


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, dict) else {}


def _email(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if "@" in text else ""
