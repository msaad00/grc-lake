"""BambooHR employment-record collector.

Reads the ``employee`` dataset through ``POST /api/v2/datasets/employee/data``
and emits one vendor-neutral ``hris.personnel.employment`` event per employee
(see :mod:`security_lakehouse.hris` for the record and PII boundary).

* :class:`BambooHRClient` — HTTP Basic auth with the API key as the username,
  as BambooHR documents. The key inherits its user's permissions, so the
  least-privilege setup is a dedicated user whose access level can only view
  the requested fields. Only the fields in :data:`DATASET_FIELDS` are
  requested; an unknown field name is a 400 from BambooHR, so a renamed field
  fails the sync instead of silently dropping evidence.
* :class:`BambooHRFixtureClient` — reads ``employee_dataset.json``.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse import netguard
from security_lakehouse.hris import EmploymentRecord, clean_hr_date, employment_event
from security_lakehouse.ingestion import backoff
from security_lakehouse.ingestion.paginate import paginate
from security_lakehouse.io import read_json

DATASET_FIELDS = (
    "eeid",
    "employeeNumber",
    "email",
    "employmentStatus",
    "hireDate",
    "terminationDate",
    "jobInformationDepartment",
    "supervisorEid",
)
PAGE_SIZE = 500
DEFAULT_TIMEOUT = 30
_COMPANY_DOMAIN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def validate_company_domain(company_domain: str) -> str:
    """The ``{companyDomain}`` in ``https://{companyDomain}.bamboohr.com``.

    Only a bare DNS label is accepted, so a configured value can never point
    the authenticated request at another host.
    """
    value = str(company_domain or "").strip()
    if not _COMPANY_DOMAIN.fullmatch(value):
        raise ValueError("company_domain must be the bare BambooHR subdomain, e.g. 'acme' for acme.bamboohr.com")
    return value


class BambooHRClient:
    """Authenticated, read-only BambooHR dataset client."""

    def __init__(self, company_domain: str, *, api_key: str, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.company_domain = validate_company_domain(company_domain)
        self._auth = "Basic " + base64.b64encode(f"{api_key}:x".encode()).decode()
        self.timeout = timeout

    @property
    def dataset_url(self) -> str:
        return f"https://{self.company_domain}.bamboohr.com/api/v2/datasets/employee/data"

    def employees(self) -> list[dict[str, Any]]:
        def fetch_page(page: int | None) -> dict[str, Any]:
            body = {"fields": list(DATASET_FIELDS), "page": page or 1, "pageSize": PAGE_SIZE}
            payload = backoff.http_retry(lambda: self._post_json(body))
            if not isinstance(payload, dict):
                raise ValueError("BambooHR returned non-object JSON for the employee dataset")
            return payload

        def extract_items(page: dict[str, Any]) -> list[dict[str, Any]]:
            return [row for row in page.get("data", []) if isinstance(row, dict)]

        def next_cursor(page: dict[str, Any]) -> int | None:
            raw_meta = page.get("meta")
            meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
            current, total = int(meta.get("page") or 1), int(meta.get("totalPages") or 1)
            return current + 1 if current < total else None

        return list(paginate(fetch_page, extract_items, next_cursor))

    def _post_json(self, body: dict[str, Any]) -> Any:
        request = urllib.request.Request(
            self.dataset_url,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={
                "accept": "application/json",
                "content-type": "application/json",
                "authorization": self._auth,
                "user-agent": "grc-lake",
            },
        )
        with netguard.open_public(request, timeout=self.timeout, label="bamboohr api") as resp:
            return json.loads(resp.read().decode("utf-8"))


class BambooHRFixtureClient:
    """Offline BambooHR client backed by a fixture directory."""

    def __init__(self, fixture_dir: str | Path, *, company_domain: str) -> None:
        self.fixture = Path(fixture_dir)
        self.company_domain = validate_company_domain(company_domain)

    @property
    def dataset_url(self) -> str:
        return f"https://{self.company_domain}.bamboohr.com/api/v2/datasets/employee/data"

    def employees(self) -> list[dict[str, Any]]:
        path = self.fixture / "employee_dataset.json"
        payload = read_json(path) if path.exists() else []
        return [row for row in payload if isinstance(row, dict)] if isinstance(payload, list) else []


def collect_bamboohr_evidence(
    client: BambooHRClient | BambooHRFixtureClient,
    *,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    now = collected_at or datetime.now(UTC)
    org = f"{client.company_domain}.bamboohr.com"
    rows: list[dict[str, Any]] = []
    for row in client.employees():
        record = _record(row)
        if record is None:
            continue
        rows.append(
            employment_event(
                record,
                vendor="bamboohr",
                org=org,
                evidence_ref=f"{client.dataset_url}#eeid={record.employee_id}",
                collected_at=now,
                tenant_id=tenant_id,
            )
        )
    return rows


def _record(row: dict[str, Any]) -> EmploymentRecord | None:
    raw_fields = row.get("fields")
    fields: dict[str, Any] = raw_fields if isinstance(raw_fields, dict) else {}
    employee_id = str(fields.get("eeid") or "").strip()
    if not employee_id:
        return None
    return EmploymentRecord(
        employee_id=employee_id,
        employee_number=_text(fields.get("employeeNumber")),
        work_email=_text(fields.get("email")),
        employment_status=_text(fields.get("employmentStatus")),
        hire_date=clean_hr_date(fields.get("hireDate")),
        termination_date=clean_hr_date(fields.get("terminationDate")),
        department=_text(fields.get("jobInformationDepartment")),
        manager_id=_text(fields.get("supervisorEid")),
    )


def _text(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None
