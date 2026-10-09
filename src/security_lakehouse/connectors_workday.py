"""Workday employment-record collector (Report-as-a-Service).

Workday's public Staffing REST worker resource carries no termination date or
work email, so this connector reads a tenant-defined custom report published
as a web service (RaaS). The customer builds the report with the columns in
:data:`WORKDAY_COLUMNS` and gives GRC Lake its JSON URL plus a read-only
integration system user (ISU). Rows map onto the vendor-neutral
``hris.personnel.employment`` event (see :mod:`security_lakehouse.hris`);
any extra report column is ignored and never written.

The report URL must be https, on a Workday-hosted domain, request
``format=json``, and carry no embedded credentials — so a configured value can
never send the ISU credentials to another host.
"""

from __future__ import annotations

import base64
import json
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse import netguard
from security_lakehouse.hris import EmploymentRecord, clean_hr_date, employment_event
from security_lakehouse.ingestion import backoff
from security_lakehouse.io import read_json

WORKDAY_COLUMNS = (
    "Employee_ID",
    "Work_Email",
    "Worker_Status",
    "Hire_Date",
    "Termination_Date",
    "Department",
    "Manager_ID",
)
WORKDAY_HOST_SUFFIXES = (".workday.com", ".myworkday.com", ".myworkdaygov.com")
DEFAULT_TIMEOUT = 60


def validate_report_url(report_url: str) -> str:
    url = str(report_url or "").strip()
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    query = urllib.parse.parse_qs(parsed.query)
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or not any(host.endswith(suffix) for suffix in WORKDAY_HOST_SUFFIXES)
        or query.get("format") != ["json"]
    ):
        raise ValueError(
            "report_url must be the https JSON URL of a Workday RaaS report on a Workday domain "
            "(…/ccx/service/customreport2/<tenant>/<owner>/<report>?format=json)"
        )
    return url


class WorkdayReportClient:
    """Read-only RaaS client authenticated as an integration system user."""

    def __init__(self, report_url: str, *, username: str, password: str, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.report_url = validate_report_url(report_url)
        self._auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        self.timeout = timeout

    def rows(self) -> list[dict[str, Any]]:
        payload = backoff.http_retry(self._get_json)
        return _report_rows(payload)

    def _get_json(self) -> Any:
        request = urllib.request.Request(
            self.report_url,
            headers={
                "accept": "application/json",
                "authorization": self._auth,
                "user-agent": "grc-lake",
            },
        )
        with netguard.open_public(request, timeout=self.timeout, label="workday report") as resp:
            return json.loads(resp.read().decode("utf-8"))


class WorkdayReportFixtureClient:
    """Offline Workday client backed by ``report.json``."""

    def __init__(self, fixture_dir: str | Path, *, report_url: str) -> None:
        self.fixture = Path(fixture_dir)
        self.report_url = validate_report_url(report_url)

    def rows(self) -> list[dict[str, Any]]:
        path = self.fixture / "report.json"
        return _report_rows(read_json(path) if path.exists() else [])


def _report_rows(payload: Any) -> list[dict[str, Any]]:
    rows = payload.get("Report_Entry", []) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise ValueError("Workday report JSON must contain a Report_Entry list")
    return [row for row in rows if isinstance(row, dict)]


def collect_workday_evidence(
    client: WorkdayReportClient | WorkdayReportFixtureClient,
    *,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    now = collected_at or datetime.now(UTC)
    org = urllib.parse.urlparse(client.report_url).hostname or "workday"
    out: list[dict[str, Any]] = []
    for row in client.rows():
        record = _record(row)
        if record is None:
            continue
        out.append(
            employment_event(
                record,
                vendor="workday",
                org=org,
                evidence_ref=f"{client.report_url.split('?', 1)[0]}#Employee_ID={record.employee_id}",
                collected_at=now,
                tenant_id=tenant_id,
            )
        )
    return out


def _record(row: dict[str, Any]) -> EmploymentRecord | None:
    employee_id = str(row.get("Employee_ID") or "").strip()
    if not employee_id:
        return None
    return EmploymentRecord(
        employee_id=employee_id,
        employee_number=employee_id,
        work_email=_text(row.get("Work_Email")),
        employment_status=_text(row.get("Worker_Status")),
        hire_date=clean_hr_date(row.get("Hire_Date")),
        termination_date=clean_hr_date(row.get("Termination_Date")),
        department=_text(row.get("Department")),
        manager_id=_text(row.get("Manager_ID")),
    )


def _text(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None
