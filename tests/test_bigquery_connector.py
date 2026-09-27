"""BigQuery lake reader (preview): parameterized, read-only, ADC; no live GCP."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import security_lakehouse.connector_runner as connector_runner
from security_lakehouse import connectors_bigquery as bq
from security_lakehouse.connector_state import append_config_event, configure_payload_error
from security_lakehouse.connectors import load_connector_catalog, validate_connector_catalog
from security_lakehouse.io import read_jsonl
from security_lakehouse.lake_mapping import resolve_mapping_ref
from security_lakehouse.validation import validate_raw_events

bigquery = pytest.importorskip("google.cloud.bigquery")
OCSF = Path(__file__).parent / "fixtures" / "ocsf"


def _spec(table: str = "security_lake.sh_findings") -> Any:
    return resolve_mapping_ref({"preset": "ocsf/compliance_finding", "source": {"table": table}})


class _Recorder:
    def __init__(self, rows: list[Any]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, Any]] = []

    def __call__(self, query: str, *, job_config: Any = None, **_: Any) -> list[Any]:
        self.calls.append((query, job_config))
        return self.rows


def _client(monkeypatch: pytest.MonkeyPatch, rows: list[Any], **kwargs: Any) -> tuple[bq.BigQueryClient, _Recorder]:
    from google.auth.credentials import AnonymousCredentials
    from google.cloud.bigquery.table import Row

    recorder = _Recorder([Row(tuple(r.values()), {k: i for i, k in enumerate(r)}) for r in rows])
    client = bq.BigQueryClient("acme-sec-prod", credentials=AnonymousCredentials(), **kwargs)
    monkeypatch.setattr(client.client, "query_and_wait", recorder)
    return client, recorder


def test_query_is_parameterized_read_only_and_cost_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    source_rows = json.loads((OCSF / "sh_findings_2_0.json").read_text(encoding="utf-8"))
    client, recorder = _client(monkeypatch, [source_rows[2]], maximum_bytes_billed=5_000_000_000)
    rows = client.fetch_mapping_rows(_spec(), since="2026-09-21T00:00:00Z", limit=100)
    [(sql, job_config)] = recorder.calls
    assert sql.startswith("SELECT ") and "`security_lake`.`sh_findings`" in sql
    assert "@p0" in sql and "@since" in sql and "2003" not in sql and "2026" not in sql
    assert job_config.use_legacy_sql is False
    assert job_config.maximum_bytes_billed == 5_000_000_000
    params = {p.name: (p.type_, p.value) for p in job_config.query_parameters}
    assert params["p0"] == ("INT64", 2003)
    assert params["since"] == ("TIMESTAMP", datetime(2026, 9, 20, 23, 0, tzinfo=UTC))
    assert rows[0]["compliance"]["control"] == "IAM.6"


def test_single_part_tables_use_the_configured_dataset(monkeypatch: pytest.MonkeyPatch) -> None:
    client, recorder = _client(monkeypatch, [], dataset="security_lake")
    client.fetch_mapping_rows(_spec("sh_findings"), since=None, limit=1)
    assert "FROM `acme-sec-prod`.`security_lake`.`sh_findings`" in recorder.calls[0][0]


def test_default_byte_cap_applies(monkeypatch: pytest.MonkeyPatch) -> None:
    client, recorder = _client(monkeypatch, [])
    client.fetch_mapping_rows(_spec(), since=None, limit=1)
    assert recorder.calls[0][1].maximum_bytes_billed == bq.DEFAULT_MAXIMUM_BYTES_BILLED


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"project": "Bad_Project"}, "project_id"),
        ({"project": "acme-sec-prod", "dataset": "bad-dataset"}, "dataset"),
        ({"project": "acme-sec-prod", "location": "us east"}, "location"),
        ({"project": "acme-sec-prod", "maximum_bytes_billed": 0}, "maximum_bytes_billed"),
    ],
)
def test_identity_fields_are_validated(kwargs: dict[str, Any], message: str) -> None:
    from google.auth.credentials import AnonymousCredentials

    project = kwargs.pop("project")
    with pytest.raises(ValueError, match=message):
        bq.BigQueryClient(project, credentials=AnonymousCredentials(), **kwargs)


def test_catalog_row_is_valid_preview_and_registered() -> None:
    assert validate_connector_catalog() == []
    row = load_connector_catalog()[bq.CONNECTOR_ID]
    assert row["collection_mode"] == "existing_lake_read"
    assert row["release_stage"] == "preview"
    assert "roles/bigquery.dataViewer" in " ".join(row["minimum_permissions"])
    assert bq.CONNECTOR_ID in connector_runner.REGISTRY


@pytest.mark.parametrize(
    ("credentials", "options", "missing"),
    [
        ({}, {"mapping": {"preset": "ocsf/api_activity", "source": {"table": "d.t"}}}, "project_id"),
        ({"project_id": "acme-sec-prod"}, {}, "mapping"),
    ],
)
def test_enablement_requires_project_and_mapping(
    credentials: dict[str, Any], options: dict[str, Any], missing: str
) -> None:
    error = configure_payload_error(
        connector_id=bq.CONNECTOR_ID, state="enabled", credentials=credentials, options=options
    )
    assert error is not None and missing in error


def test_fixture_sync_through_the_runner(tmp_path: Path) -> None:
    fixtures = tmp_path / "fx"
    fixtures.mkdir()
    (fixtures / "security_lake.sh_findings.json").write_text(
        (OCSF / "sh_findings_2_0.json").read_text(), encoding="utf-8"
    )
    lake = tmp_path / "lake"
    append_config_event(
        lake,
        connector_id=bq.CONNECTOR_ID,
        state="enabled",
        actor="t",
        credentials={"project_id": "acme-sec-prod"},
        options={"mapping": {"preset": "ocsf/compliance_finding", "source": {"table": "security_lake.sh_findings"}}},
    )
    result = connector_runner.run_connector_sync(
        lake, connector_id=bq.CONNECTOR_ID, fixture_dir=fixtures, materialize=False
    )
    raw = read_jsonl(lake / connector_runner.CONNECTOR_RAW_FILE)
    assert result.evidence_count == 2
    assert validate_raw_events(raw) == []
    assert {row["status"] for row in raw} == {"open", "pass"}
