"""Malformed evidence must fail before mutations on every shared boundary."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from security_lakehouse.io import append_jsonl, read_json, read_jsonl, write_json, write_jsonl
from security_lakehouse.server_app import create_app
from security_lakehouse.validation import validate_raw_event

INVALID_JSON = [
    b"{broken",
    b'{"status":"fail","status":"pass"}',
    b'{"framework_id":NaN}',
    b'{"framework_id":Infinity}',
    b'{"framework_id":-Infinity}',
    b'{"framework_id":1e400}',
    b'{"framework_id":"\\ud800"}',
    b'{"nested":{"x":1,"x":2}}',
    b'{"x":' + b"[" * 80 + b"0" + b"]" * 80 + b"}",
]


@pytest.mark.parametrize("raw", INVALID_JSON)
def test_json_and_jsonl_reads_reject_invalid_values(tmp_path, raw):
    path = tmp_path / "input.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        read_json(path)
    with pytest.raises(ValueError):
        read_jsonl(path)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), "\ud800", {1: "nonstring key"}])
@pytest.mark.parametrize("writer", ["json", "jsonl", "append"])
def test_invalid_write_preserves_existing_bytes(tmp_path, value, writer):
    path = tmp_path / "record.jsonl"
    path.write_text('{"valid":true}\n')
    before = path.read_bytes()
    with pytest.raises((ValueError, TypeError)):
        if writer == "json":
            write_json(path, {"invalid": value})
        elif writer == "jsonl":
            write_jsonl(path, [{"valid": False}, {"invalid": value}])
        else:
            append_jsonl(path, {"invalid": value})
    assert path.read_bytes() == before
    assert list(tmp_path.glob("*.tmp")) == []


@pytest.fixture
def client(tmp_path):
    from test_api_v1 import _seed_lake

    _seed_lake(tmp_path)
    with TestClient(create_app(tmp_path, require_auth=False), raise_server_exceptions=False) as client:
        yield client


@pytest.mark.parametrize("raw", INVALID_JSON)
def test_raw_mutation_rejected_without_persisting_share(client, tmp_path, raw):
    response = client.post("/api/v1/trust-shares", content=raw, headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "bad_request"
    assert not (tmp_path / "gold/trust_shares.jsonl").exists()
    assert client.get("/api/v1/trust-shares").status_code == 200


@pytest.mark.parametrize("raw", [b'{"title":"first","title":"second"}', b'{"title":"\\ud800"}'])
def test_typed_mutation_uses_same_json_boundary(client, raw):
    response = client.post("/api/v1/remediation/tasks", content=raw, headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert client.get("/api/v1/remediation/tasks").json()["data"] == []


def raw_event():
    path = Path(__file__).resolve().parents[1] / "data/raw/security_events.jsonl"
    return json.loads(path.read_text().splitlines()[0])


@pytest.mark.parametrize(
    "patch",
    [
        {"entity": None},
        {"controls": None},
        {"controls": [1]},
        {"event_id": 123},
        {"tenant_id": None},
        {"evidence": {"collected_at": "not-a-timestamp"}},
        {"event_time": "2026-01-01T00:00:00"},
        {"attributes": {"confidence": float("nan")}},
    ],
)
def test_raw_validator_rejects_invalid_shapes_and_values(patch):
    row = {**copy.deepcopy(raw_event()), **patch}
    assert validate_raw_event(row)


def test_live_openapi_includes_the_dispatched_read_routes(client):
    spec = client.get("/openapi.json").json()
    assert "/api/v1/evidence" in spec["paths"]
    assert "/api/v1/posture/current" in spec["paths"]
    assert "/api/v1/{rest}" not in spec["paths"]


def test_valid_provider_extension_roundtrips_unchanged(tmp_path):
    row = raw_event()
    row["provider_extension"] = {"labels": ["a", "😀"], "confidence": 0.75}
    assert validate_raw_event(row) == []
    path = tmp_path / "events.jsonl"
    write_jsonl(path, [row])
    assert read_jsonl(path) == [row]


def test_rejected_ingestion_preserves_active_generation(tmp_path):
    from security_lakehouse.pipeline import run_pipeline

    raw = tmp_path / "input.jsonl"
    write_jsonl(raw, [raw_event()])
    lake = tmp_path / "lake"
    run_pipeline(raw, lake)
    generation = (lake / ".active-generation").readlink()
    before = (lake / "silver/normalized_events.jsonl").read_bytes()
    raw.write_bytes(b'{"event_id":"bad","event_id":"ambiguous"}\n')
    with pytest.raises(ValueError):
        run_pipeline(raw, lake)
    assert (lake / ".active-generation").readlink() == generation
    assert (lake / "silver/normalized_events.jsonl").read_bytes() == before


def test_lowercase_utc_designator_matches_schema_and_normalizes(tmp_path):
    from security_lakehouse.pipeline import run_pipeline

    event = raw_event()
    event["event_time"] = "2026-01-01t12:00:00z"
    event["evidence"]["collected_at"] = "2026-01-02T02:00:00+14:00"
    assert validate_raw_event(event) == []
    path = tmp_path / "events.jsonl"
    write_jsonl(path, [event])
    lake = tmp_path / "lake"
    run_pipeline(path, lake)
    silver = read_jsonl(lake / "silver/normalized_events.jsonl")[0]
    assert silver["event_time"] == silver["evidence_collected_at"] == "2026-01-01T12:00:00Z"


def test_direct_api_dispatch_rejects_nonfinite_before_writing(tmp_path):
    from security_lakehouse import api_v1

    status, body = api_v1.handle_post("/api/v1/trust-shares", {"framework_id": float("nan")}, tmp_path)
    assert status == 400
    assert body["errors"]
    assert not (tmp_path / "gold/trust_shares.jsonl").exists()


def test_existing_corrupt_share_returns_explicit_error_without_rewriting(client, tmp_path):
    path = tmp_path / "gold/trust_shares.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = b'{"share_id":"invalid","framework_id":NaN}\n'
    path.write_bytes(raw)
    response = client.get("/api/v1/trust-shares")
    assert response.status_code == 503
    assert response.json()["errors"][0]["code"] == "invalid_stored_data"
    assert path.read_bytes() == raw


def test_json_nesting_characters_in_strings_are_not_structure(tmp_path):
    row = {"text": '["' * 100 + "\\" * 100}
    path = tmp_path / "literal.json"
    write_json(path, row)
    assert read_json(path) == row


def test_declared_schema_and_runtime_reject_same_invalid_event_shapes():
    from jsonschema import Draft202012Validator, FormatChecker

    from security_lakehouse.validation import evidence_timestamp

    checker = FormatChecker()

    @checker.checks("date-time", raises=(ValueError, TypeError))
    def timestamp(value):
        evidence_timestamp(value)
        return True

    schema = json.loads(
        (Path(__file__).resolve().parents[1] / "data/schemas/raw-security-event.schema.json").read_text()
    )
    validator = Draft202012Validator(schema, format_checker=checker)
    for patch in [
        {"entity": None},
        {"controls": None},
        {"controls": [1]},
        {"event_id": 1},
        {"event_time": "2026-01-01T12:00:00"},
        {"event_time": "2026-99-01T00:00:00Z"},
        {"evidence": {"collected_at": "2026-01-01T00:00:00"}},
        {"evidence": {"collected_at": "2026-99-01T00:00:00Z"}},
    ]:
        row = {**raw_event(), **patch}
        assert list(validator.iter_errors(row)), patch
        assert validate_raw_event(row), patch
