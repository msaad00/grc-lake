"""Rippling employment-record collector.

Reads ``GET https://rest.ripplingapis.com/workers/`` (Rippling REST API,
scope ``workers.read``) and emits one vendor-neutral
``hris.personnel.employment`` event per worker (see
:mod:`security_lakehouse.hris`).

The workers endpoint has no field selection, so the response can carry fields
outside the GRC Lake PII boundary (date of birth, gender, compensation ids,
personal email). :func:`_record` copies only the allowlisted fields; nothing
else is retained or written. Pagination follows ``next_link`` only while it
stays on ``https://rest.ripplingapis.com`` so the bearer token is never sent
to another host.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_lakehouse import netguard
from security_lakehouse.hris import EmploymentRecord, clean_hr_date, employment_event
from security_lakehouse.ingestion import backoff
from security_lakehouse.ingestion.paginate import paginate
from security_lakehouse.io import read_json

RIPPLING_HOST = "rest.ripplingapis.com"
WORKERS_URL = f"https://{RIPPLING_HOST}/workers/?limit=100"
DEFAULT_TIMEOUT = 30


class RipplingClient:
    """Authenticated, read-only Rippling REST API client."""

    def __init__(self, *, token: str, timeout: int = DEFAULT_TIMEOUT) -> None:
        self._token = token
        self.timeout = timeout

    def workers(self) -> list[dict[str, Any]]:
        def fetch_page(url: str | None) -> dict[str, Any]:
            page_url = url or WORKERS_URL
            payload = backoff.http_retry(lambda: self._get_json(page_url))
            if not isinstance(payload, dict):
                raise ValueError("Rippling returned non-object JSON for workers")
            return payload

        def extract_items(page: dict[str, Any]) -> list[dict[str, Any]]:
            return [row for row in page.get("results", []) if isinstance(row, dict)]

        def next_cursor(page: dict[str, Any]) -> str | None:
            next_link = str(page.get("next_link") or "")
            if not next_link:
                return None
            parsed = urllib.parse.urlparse(next_link)
            if parsed.scheme != "https" or parsed.hostname != RIPPLING_HOST:
                raise ValueError(f"refusing next_link outside https://{RIPPLING_HOST}")
            return next_link

        return list(paginate(fetch_page, extract_items, next_cursor))

    def _get_json(self, url: str) -> Any:
        request = urllib.request.Request(
            url,
            headers={
                "accept": "application/json",
                "authorization": f"Bearer {self._token}",
                "user-agent": "grc-lake",
            },
        )
        with netguard.open_public(request, timeout=self.timeout, label="rippling api") as resp:
            return json.loads(resp.read().decode("utf-8"))


class RipplingFixtureClient:
    """Offline Rippling client backed by ``workers.json``."""

    def __init__(self, fixture_dir: str | Path) -> None:
        self.fixture = Path(fixture_dir)

    def workers(self) -> list[dict[str, Any]]:
        path = self.fixture / "workers.json"
        payload = read_json(path) if path.exists() else []
        return [row for row in payload if isinstance(row, dict)] if isinstance(payload, list) else []


def collect_rippling_evidence(
    client: RipplingClient | RipplingFixtureClient,
    *,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    now = collected_at or datetime.now(UTC)
    rows: list[dict[str, Any]] = []
    for worker in client.workers():
        record = _record(worker)
        if record is None:
            continue
        rows.append(
            employment_event(
                record,
                vendor="rippling",
                org=RIPPLING_HOST,
                evidence_ref=f"https://{RIPPLING_HOST}/workers/{urllib.parse.quote(record.employee_id)}",
                collected_at=now,
                tenant_id=tenant_id,
            )
        )
    return rows


def _record(worker: dict[str, Any]) -> EmploymentRecord | None:
    worker_id = str(worker.get("id") or "").strip()
    if not worker_id:
        return None
    return EmploymentRecord(
        employee_id=worker_id,
        employee_number=_text(worker.get("number")),
        work_email=_text(worker.get("work_email")),
        employment_status=_text(worker.get("status")),
        hire_date=clean_hr_date(worker.get("start_date")),
        termination_date=clean_hr_date(worker.get("end_date")),
        department=_text(worker.get("department_id")),
        manager_id=_text(worker.get("manager_id")),
    )


def _text(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None
