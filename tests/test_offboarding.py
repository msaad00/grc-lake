"""HR termination ↔ identity-provider account correlation."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

import security_lakehouse.connector_runner as connector_runner
from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.connector_state import append_config_event
from security_lakehouse.hris import EmploymentRecord, employment_event
from security_lakehouse.io import read_jsonl
from security_lakehouse.offboarding import (
    OFFBOARDING_CONNECTOR_ID,
    OFFBOARDING_CONTROLS,
    correlate_offboarding,
)
from security_lakehouse.validation import validate_raw_events

AS_OF = date(2026, 6, 3)
COLLECTED = datetime(2026, 6, 3, tzinfo=UTC)


def _hr(employee_id: str, email: str, termination_date: str | None) -> dict[str, Any]:
    record = EmploymentRecord(
        employee_id=employee_id,
        employee_number=None,
        work_email=email,
        employment_status=None,
        hire_date="2024-01-01",
        termination_date=termination_date,
        department=None,
        manager_id=None,
    )
    return employment_event(
        record, vendor="bamboohr", org="acme.bamboohr.com", evidence_ref="ref", collected_at=COLLECTED, tenant_id="t"
    )


def _okta(user_id: str, login: str, *, can_authenticate: bool) -> dict[str, Any]:
    return {
        "event_id": f"okta-{user_id}",
        "source": "okta",
        "event_type": "okta.identity.user_access",
        "entity": {"asset_id": f"okta:user:{user_id}"},
        "attributes": {"user_id": user_id, "login": login, "can_authenticate": can_authenticate},
    }


def _google(user_id: str, email: str, *, can_authenticate: bool) -> dict[str, Any]:
    return {
        "event_id": f"gw-{user_id}",
        "source": "google_workspace",
        "event_type": "google_workspace.identity.user_access",
        "entity": {"asset_id": f"google_workspace:user:{user_id}"},
        "attributes": {"user_id": user_id, "primary_email": email, "can_authenticate": can_authenticate},
    }


def _by_employee(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {r["attributes"]["employee_id"]: r for r in rows}


def test_controls_exist_and_fail_on_open_violations() -> None:
    catalog = load_control_catalog()
    for control_id in OFFBOARDING_CONTROLS:
        assert catalog[control_id]["evaluation_rule"] in {
            "fail_when_missing_evidence",
            "fail_when_open_violation_or_stale_evidence",
        }


def test_terminated_employee_with_active_idp_account_is_a_high_finding() -> None:
    rows = correlate_offboarding(
        [_hr("102", "Grace@Example.com", "2026-05-15"), _okta("u2", "grace@example.com", can_authenticate=True)],
        as_of=AS_OF,
        collected_at=COLLECTED,
    )

    finding = _by_employee(rows)["102"]
    assert (finding["status"], finding["severity"]) == ("open", "high")
    assert finding["attributes"]["outcome"] == "active_after_termination"
    assert finding["attributes"]["days_since_termination"] == 19
    assert finding["attributes"]["active_accounts"] == [{"source": "okta", "account_id": "okta:user:u2"}]
    assert finding["controls"] == OFFBOARDING_CONTROLS
    assert finding["attributes"]["data_sensitivity"] == "confidential"
    assert validate_raw_events(rows) == []


def test_any_active_account_across_idps_is_a_finding() -> None:
    rows = correlate_offboarding(
        [
            _hr("102", "grace@example.com", "2026-05-15"),
            _okta("u2", "grace@example.com", can_authenticate=False),
            _google("g2", "grace@example.com", can_authenticate=True),
        ],
        as_of=AS_OF,
        collected_at=COLLECTED,
    )
    assert _by_employee(rows)["102"]["status"] == "open"


def test_deprovisioned_everywhere_passes() -> None:
    rows = correlate_offboarding(
        [
            _hr("102", "grace@example.com", "2026-05-15"),
            _okta("u2", "grace@example.com", can_authenticate=False),
            _google("g2", "grace@example.com", can_authenticate=False),
        ],
        as_of=AS_OF,
        collected_at=COLLECTED,
    )
    finding = _by_employee(rows)["102"]
    assert (finding["status"], finding["attributes"]["outcome"]) == ("pass", "deprovisioned")


def test_active_account_inside_grace_period_is_not_yet_a_violation() -> None:
    rows = correlate_offboarding(
        [_hr("105", "new@example.com", "2026-06-03"), _okta("u5", "new@example.com", can_authenticate=True)],
        as_of=AS_OF,
        collected_at=COLLECTED,
    )
    finding = _by_employee(rows)["105"]
    assert (finding["status"], finding["attributes"]["outcome"]) == ("observed", "within_grace_period")


def test_terminated_employee_with_no_matching_account_is_not_a_pass() -> None:
    rows = correlate_offboarding(
        [_hr("106", "ghost@example.com", "2026-05-01"), _okta("u1", "someone@example.com", can_authenticate=True)],
        as_of=AS_OF,
        collected_at=COLLECTED,
    )
    finding = _by_employee(rows)["106"]
    assert (finding["status"], finding["attributes"]["outcome"]) == ("observed", "no_idp_account_matched")


def test_active_and_future_terminations_are_ignored() -> None:
    rows = correlate_offboarding(
        [
            _hr("101", "ada@example.com", None),
            _hr("103", "alan@example.com", "2026-12-31"),
            _okta("u1", "ada@example.com", can_authenticate=True),
            _okta("u3", "alan@example.com", can_authenticate=True),
        ],
        as_of=AS_OF,
        collected_at=COLLECTED,
    )
    assert rows == []


def test_no_correlation_without_both_hr_and_idp_evidence() -> None:
    assert correlate_offboarding([_hr("102", "g@example.com", "2026-05-15")], as_of=AS_OF, collected_at=COLLECTED) == []
    assert (
        correlate_offboarding(
            [_okta("u2", "g@example.com", can_authenticate=True)], as_of=AS_OF, collected_at=COLLECTED
        )
        == []
    )


def test_grace_days_is_configurable() -> None:
    rows = correlate_offboarding(
        [_hr("102", "grace@example.com", "2026-05-15"), _okta("u2", "grace@example.com", can_authenticate=True)],
        as_of=AS_OF,
        collected_at=COLLECTED,
        grace_days=30,
    )
    assert _by_employee(rows)["102"]["attributes"]["outcome"] == "within_grace_period"


def _okta_fixture(tmp_path: Path, users: list[dict[str, Any]]) -> Path:
    directory = tmp_path / "okta-fixture"
    shutil.copytree(Path(__file__).parent / "fixtures" / "okta", directory)
    (directory / "users.json").write_text(json.dumps(users))
    return directory


def test_syncs_refresh_offboarding_findings_in_either_order(tmp_path: Path) -> None:
    lake = tmp_path / "lake"
    append_config_event(lake, connector_id="okta-identity", state="enabled", actor="a")
    append_config_event(
        lake,
        connector_id="bamboohr-personnel",
        state="enabled",
        actor="a",
        credentials={"company_domain": "acme", "credential_ref": "BAMBOOHR_API_KEY"},
    )
    active = _okta_fixture(
        tmp_path,
        [{"id": "u102", "status": "ACTIVE", "profile": {"login": "grace@example.com"}}],
    )

    connector_runner.run_connector_sync(lake, connector_id="okta-identity", fixture_dir=active, materialize=False)
    raw_path = lake / connector_runner.CONNECTOR_RAW_FILE
    assert not [r for r in read_jsonl(raw_path) if r.get("connector_id") == OFFBOARDING_CONNECTOR_ID]

    connector_runner.run_connector_sync(
        lake, connector_id="bamboohr-personnel", fixture_dir=Path(__file__).parent / "fixtures" / "bamboohr"
    )
    derived = [r for r in read_jsonl(raw_path) if r.get("connector_id") == OFFBOARDING_CONNECTOR_ID]
    assert [(r["attributes"]["employee_id"], r["status"]) for r in derived] == [("102", "open")]
    posture = {
        json.loads(line)["control_id"]: json.loads(line) for line in (lake / "gold" / "control_posture.jsonl").open()
    }
    assert posture["SOC2-CC6.2"]["status"] == "fail"

    # Deprovisioning in the IdP clears the finding on the next IdP sync.
    deprovisioned = _okta_fixture(
        tmp_path / "second",
        [{"id": "u102", "status": "DEPROVISIONED", "profile": {"login": "grace@example.com"}}],
    )
    connector_runner.run_connector_sync(
        lake, connector_id="okta-identity", fixture_dir=deprovisioned, materialize=False
    )
    derived = [r for r in read_jsonl(raw_path) if r.get("connector_id") == OFFBOARDING_CONNECTOR_ID]
    assert [(r["attributes"]["employee_id"], r["status"]) for r in derived] == [("102", "pass")]


@pytest.mark.parametrize("value", ["-1", "abc", "400"])
def test_invalid_grace_env_falls_back_to_default(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    from security_lakehouse.offboarding import DEFAULT_GRACE_DAYS, grace_days_from_env

    assert grace_days_from_env({"GRC_LAKE_OFFBOARDING_GRACE_DAYS": value}) == DEFAULT_GRACE_DAYS
    assert grace_days_from_env({"GRC_LAKE_OFFBOARDING_GRACE_DAYS": "7"}) == 7
