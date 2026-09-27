"""Databricks evidence-lake collector.

An existing-lake reader, like ``snowflake-evidence-lake``: TrustOps reads the
same four TrustOps evidence views (``TRUSTOPS_AUDIT_EVENTS``,
``TRUSTOPS_CONTROL_POSTURE``, ``TRUSTOPS_ASSET_RISK``,
``TRUSTOPS_EVIDENCE_BUNDLES``) from a Unity Catalog schema and never creates,
updates, or deletes workspace objects. ``deploy/databricks/bootstrap_poc.sql``
provisions the views over ``system.access.audit``.

Reads go through the Databricks SQL Statement Execution API
(``/api/2.0/sql/statements``) on a SQL warehouse, so no Databricks SDK or
driver dependency is needed. Authentication is OAuth machine-to-machine: a
service principal's client id and secret mint a one-hour workspace token at
``/oidc/v1/token`` (``grant_type=client_credentials``, ``scope=all-apis``).
Least privilege is ``CAN USE`` on the warehouse plus ``USE CATALOG``,
``USE SCHEMA``, and ``SELECT`` on the evidence views; on SQL warehouses the
view owner's permissions govern the underlying system tables.

Every request goes to the configured workspace host only: the host must be a
Databricks workspace domain, result chunk links must be relative paths or stay
on that host, and catalog/schema/view names are strict identifiers quoted with
backticks.
"""

from __future__ import annotations

import base64
import json
import re
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from security_lakehouse import netguard
from security_lakehouse.connectors_snowflake import DEFAULT_VIEWS, collect_snowflake_evidence
from security_lakehouse.ingestion import backoff
from security_lakehouse.ingestion.paginate import paginate
from security_lakehouse.io import read_json
from security_lakehouse.lake_mapping import MappingSpec, compile_select, read_fixture_table

CONNECTOR_ID = "databricks-evidence-lake"
SOURCE = "databricks"
WORKSPACE_HOST_SUFFIXES = (".cloud.databricks.com", ".azuredatabricks.net", ".gcp.databricks.com")
_HOST = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_]{1,255}$")
DEFAULT_TIMEOUT = 60
WAIT_TIMEOUT = "30s"
POLL_SECONDS = 2.0
MAX_POLLS = 150
PENDING_STATES = {"PENDING", "RUNNING"}


def validate_workspace_host(host: str) -> str:
    value = str(host or "").strip().lower()
    if not _HOST.fullmatch(value) or not value.endswith(WORKSPACE_HOST_SUFFIXES):
        raise ValueError(
            "host must be a bare Databricks workspace hostname "
            "(*.cloud.databricks.com, *.azuredatabricks.net, or *.gcp.databricks.com)"
        )
    return value


def validate_identifier(name: str) -> str:
    value = str(name or "").strip()
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"invalid Unity Catalog identifier {name!r}: use letters, digits, and underscores only")
    return value


class DatabricksClient:
    """Read-only client for TrustOps evidence views on a Databricks SQL warehouse."""

    def __init__(
        self,
        host: str,
        *,
        client_id: str,
        client_secret: str,
        warehouse_id: str,
        catalog: str,
        schema: str,
        views: dict[str, str] | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.host = validate_workspace_host(host)
        self.account = self.host
        self._basic = "Basic " + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        self.warehouse_id = validate_identifier(warehouse_id)
        self.catalog = validate_identifier(catalog)
        self.schema = validate_identifier(schema)
        self.views = {key: validate_identifier(name) for key, name in (views or DEFAULT_VIEWS).items()}
        self.timeout = timeout
        self._sleep = sleep
        self._token: str | None = None

    def audit_events(self) -> list[dict[str, Any]]:
        return self._select_view("audit_events")

    def control_posture(self) -> list[dict[str, Any]]:
        return self._select_view("control_posture")

    def asset_risk(self) -> list[dict[str, Any]]:
        return self._select_view("asset_risk")

    def evidence_bundles(self) -> list[dict[str, Any]]:
        return self._select_view("evidence_bundles")

    def fetch_mapping_rows(self, spec: MappingSpec, *, since: str | None, limit: int) -> list[dict[str, Any]]:
        """Read a customer table through a mapping spec with named ``:param`` markers.

        A one-part table name is qualified with the configured catalog and schema.
        """
        query = compile_select(
            spec, "databricks", since=since, limit=limit, default_namespace=(self.catalog, self.schema)
        )
        return self._execute(query.sql, query.databricks_parameters())

    def _select_view(self, key: str) -> list[dict[str, Any]]:
        statement = f"SELECT * FROM `{self.catalog}`.`{self.schema}`.`{self.views[key]}`"  # noqa: S608
        return self._execute(statement, [])

    def _execute(self, statement: str, parameters: list[dict[str, str]]) -> list[dict[str, Any]]:
        body: dict[str, Any] = {
            "statement": statement,
            "warehouse_id": self.warehouse_id,
            "wait_timeout": WAIT_TIMEOUT,
            "on_wait_timeout": "CONTINUE",
            "disposition": "INLINE",
            "format": "JSON_ARRAY",
        }
        if parameters:
            body["parameters"] = parameters
        response = self._await(self._request("POST", "/api/2.0/sql/statements", body))
        columns = [
            str(col.get("name")) for col in ((response.get("manifest") or {}).get("schema") or {}).get("columns", [])
        ]
        first = response.get("result") or {}

        def fetch_page(link: str | None) -> dict[str, Any]:
            return first if link is None else self._request("GET", link)

        def extract_items(page: dict[str, Any]) -> list[dict[str, Any]]:
            return [dict(zip(columns, row, strict=False)) for row in page.get("data_array") or []]

        def next_cursor(page: dict[str, Any]) -> str | None:
            link = str(page.get("next_chunk_internal_link") or "")
            if not link:
                return None
            parsed = urllib.parse.urlparse(link)
            if parsed.scheme or parsed.netloc:
                if parsed.scheme != "https" or parsed.hostname != self.host:
                    raise ValueError("refusing a result chunk link outside the configured Databricks workspace")
                link = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            return link

        return list(paginate(fetch_page, extract_items, next_cursor))

    def _await(self, response: dict[str, Any]) -> dict[str, Any]:
        statement_id = urllib.parse.quote(str(response.get("statement_id") or ""), safe="")
        for _ in range(MAX_POLLS):
            status = response.get("status") or {}
            state = str(status.get("state") or "")
            if state == "SUCCEEDED":
                return response
            if state not in PENDING_STATES:
                message = str((status.get("error") or {}).get("message") or state or "unknown state")
                raise RuntimeError(f"Databricks statement did not succeed: {message}")
            self._sleep(POLL_SECONDS)
            response = self._request("GET", f"/api/2.0/sql/statements/{statement_id}")
        raise RuntimeError("Databricks statement did not finish within the polling budget")

    def _bearer(self) -> str:
        if self._token is None:
            request = urllib.request.Request(
                f"https://{self.host}/oidc/v1/token",
                data=b"grant_type=client_credentials&scope=all-apis",
                method="POST",
                headers={
                    "authorization": self._basic,
                    "content-type": "application/x-www-form-urlencoded",
                    "accept": "application/json",
                    "user-agent": "trustops-security-data-lake",
                },
            )
            payload = backoff.http_retry(lambda: self._open(request))
            token = str((payload or {}).get("access_token") or "")
            if not token:
                raise RuntimeError("Databricks OAuth token response did not include an access_token")
            self._token = token
        return self._token

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        request = urllib.request.Request(
            f"https://{self.host}{path}",
            data=json.dumps(body).encode("utf-8") if body is not None else None,
            method=method,
            headers={
                "authorization": f"Bearer {self._bearer()}",
                "content-type": "application/json",
                "accept": "application/json",
                "user-agent": "trustops-security-data-lake",
            },
        )
        payload = backoff.http_retry(lambda: self._open(request))
        if not isinstance(payload, dict):
            raise ValueError("Databricks returned non-object JSON")
        return payload

    def _open(self, request: urllib.request.Request) -> Any:
        with netguard.open_public(request, timeout=self.timeout, label="databricks workspace") as resp:
            return json.loads(resp.read().decode("utf-8"))


class DatabricksFixtureClient:
    """Offline client reading the four evidence views from JSON fixtures."""

    def __init__(self, fixture_dir: str | Path, *, host: str) -> None:
        self.fixture = Path(fixture_dir)
        self.account = validate_workspace_host(host)

    def audit_events(self) -> list[dict[str, Any]]:
        return self._read("audit_events.json")

    def control_posture(self) -> list[dict[str, Any]]:
        return self._read("control_posture.json")

    def asset_risk(self) -> list[dict[str, Any]]:
        return self._read("asset_risk.json")

    def evidence_bundles(self) -> list[dict[str, Any]]:
        return self._read("evidence_bundles.json")

    def fetch_mapping_rows(self, spec: MappingSpec, *, since: str | None, limit: int) -> list[dict[str, Any]]:
        _ = since, limit  # fixtures return the whole table; map_rows applies the same bound
        return read_fixture_table(self.fixture, spec.source_table)

    def _read(self, name: str) -> list[dict[str, Any]]:
        path = self.fixture / name
        payload = read_json(path) if path.exists() else []
        return [row for row in payload if isinstance(row, dict)] if isinstance(payload, list) else []


def collect_databricks_evidence(
    client: DatabricksClient | DatabricksFixtureClient,
    *,
    collected_at: datetime | None = None,
    tenant_id: str = "customer-managed",
) -> list[dict[str, Any]]:
    return collect_snowflake_evidence(
        client, account=client.account, collected_at=collected_at, tenant_id=tenant_id, source=SOURCE
    )
