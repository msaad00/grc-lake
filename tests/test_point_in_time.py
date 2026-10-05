"""Point-in-time posture-as-of query over immutable assessment snapshots."""

from __future__ import annotations

import json
from http import HTTPStatus
from pathlib import Path

import pytest

from security_lakehouse import api_v1
from security_lakehouse.assessment import list_snapshot_times, posture_as_of


def _write_snapshot(lake: Path, evaluated_at: str, *, score: float, reason: str = "manual") -> Path:
    """Craft a minimal assessment snapshot file with a controlled evaluated_at."""
    snapshots_dir = lake / "gold" / "snapshots"
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    ts = evaluated_at.replace(":", "").replace("-", "")
    path = snapshots_dir / f"assessment-{ts}.json"
    payload = {
        "schema_version": "trustops.assessment.v1",
        "assessment_type": "point_in_time_snapshot",
        "evaluated_at": evaluated_at,
        "snapshot_reason": reason,
        "posture": {"score": score, "state": "ready", "open_violation_count": 0},
        "frameworks": [{"framework": "SOC 2", "score": score}],
        "assessment_hash": f"hash-{ts}",
    }
    from security_lakehouse.assessment import _assessment_hash, _ledger_path
    from security_lakehouse.io import append_jsonl, read_jsonl

    ledger = read_jsonl(_ledger_path(lake), missing_ok=True)
    payload["prev_hash"] = ledger[-1]["assessment_hash"] if ledger else None
    payload["assessment_hash"] = _assessment_hash(payload)
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    append_jsonl(
        _ledger_path(lake),
        {
            "snapshot": path.name,
            "evaluated_at": evaluated_at,
            "prev_hash": payload["prev_hash"],
            "assessment_hash": payload["assessment_hash"],
        },
    )
    return path


def _seed_three(lake: Path) -> None:
    _write_snapshot(lake, "2026-01-01T00:00:00Z", score=70.0)
    _write_snapshot(lake, "2026-03-01T00:00:00Z", score=85.0)
    _write_snapshot(lake, "2026-05-01T00:00:00Z", score=92.0)


def test_list_snapshot_times_is_ordered(tmp_path: Path) -> None:
    _seed_three(tmp_path)
    assert list_snapshot_times(tmp_path) == [
        "2026-01-01T00:00:00Z",
        "2026-03-01T00:00:00Z",
        "2026-05-01T00:00:00Z",
    ]


def test_posture_as_of_picks_most_recent_at_or_before(tmp_path: Path) -> None:
    _seed_three(tmp_path)
    result = posture_as_of(tmp_path, as_of="2026-04-15")
    assert result["found"] is True
    assert result["evaluated_at"] == "2026-03-01T00:00:00Z"
    expected = json.loads((tmp_path / "gold/snapshots/assessment-20260301T000000Z.json").read_text())
    assert result["assessment_hash"] == expected["assessment_hash"]
    assert result["posture"]["score"] == 85.0
    assert result["requested_as_of"] == "2026-04-15T00:00:00Z"
    assert result["available_from"] == "2026-01-01T00:00:00Z"


def test_posture_as_of_exact_match_is_inclusive(tmp_path: Path) -> None:
    _seed_three(tmp_path)
    result = posture_as_of(tmp_path, as_of="2026-03-01T00:00:00Z")
    assert result["found"] is True
    assert result["evaluated_at"] == "2026-03-01T00:00:00Z"


def test_posture_as_of_future_date_returns_latest(tmp_path: Path) -> None:
    _seed_three(tmp_path)
    result = posture_as_of(tmp_path, as_of="2027-01-01")
    assert result["found"] is True
    assert result["evaluated_at"] == "2026-05-01T00:00:00Z"
    assert result["posture"]["score"] == 92.0


def test_posture_as_of_before_first_snapshot_is_empty(tmp_path: Path) -> None:
    _seed_three(tmp_path)
    result = posture_as_of(tmp_path, as_of="2025-06-01")
    assert result["found"] is False
    assert result["posture"] is None
    assert result["evaluated_at"] is None
    assert result["available_from"] == "2026-01-01T00:00:00Z"
    assert result["requested_as_of"] == "2025-06-01T00:00:00Z"


def test_posture_as_of_no_snapshots_available_from_none(tmp_path: Path) -> None:
    result = posture_as_of(tmp_path, as_of="2026-05-01")
    assert result["found"] is False
    assert result["available_from"] is None
    assert result["snapshot_count"] == 0


def test_handle_get_posture_as_of_envelope(tmp_path: Path) -> None:
    _seed_three(tmp_path)
    status, body = api_v1.handle_get("/api/v1/posture/as-of", {"as_of": ["2026-04-15"]}, tmp_path)
    assert status == HTTPStatus.OK
    assert body["meta"]["resource"] == "posture.as_of"
    assert body["errors"] == []
    assert body["data"]["evaluated_at"] == "2026-03-01T00:00:00Z"


def test_handle_get_posture_as_of_missing_param_is_400(tmp_path: Path) -> None:
    _seed_three(tmp_path)
    status, body = api_v1.handle_get("/api/v1/posture/as-of", {}, tmp_path)
    assert status == HTTPStatus.BAD_REQUEST
    assert body["errors"][0]["code"] == "bad_request"


def test_handle_get_posture_as_of_invalid_param_is_400(tmp_path: Path) -> None:
    _seed_three(tmp_path)
    status, body = api_v1.handle_get("/api/v1/posture/as-of", {"as_of": ["not-a-date"]}, tmp_path)
    assert status == HTTPStatus.BAD_REQUEST
    assert body["errors"][0]["code"] == "bad_request"


def test_cli_posture_as_of(tmp_path: Path, capsys) -> None:
    from security_lakehouse.cli import main

    _seed_three(tmp_path)
    rc = main(["assessment", "posture-as-of", "--lake", str(tmp_path), "--as-of", "2026-04-15"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["found"] is True
    assert out["evaluated_at"] == "2026-03-01T00:00:00Z"


def test_cli_posture_as_of_before_first_is_exit_1(tmp_path: Path, capsys) -> None:
    from security_lakehouse.cli import main

    _seed_three(tmp_path)
    rc = main(["assessment", "posture-as-of", "--lake", str(tmp_path), "--as-of", "2020-01-01"])
    assert rc == 1
    assert json.loads(capsys.readouterr().out)["found"] is False


def test_posture_as_of_listed_in_catalog() -> None:
    catalog = api_v1.resource_catalog()
    row = next((r for r in catalog if r["path"] == "/api/v1/posture/as-of"), None)
    assert row is not None
    assert row["resource"] == "posture.as_of"
    assert row["query"] == ["as_of"]
    assert row["methods"] == ["GET"]


def test_http_posture_as_of_over_testclient(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    pytest.importorskip("sqlalchemy")
    from fastapi.testclient import TestClient

    from security_lakehouse.server_app import create_app
    from test_api_v1 import _seed_lake

    # _seed_lake writes silver/ so the root is a recognised flat lake; the
    # insecure no-auth tenant then binds to it and reads the snapshots below.
    _seed_lake(tmp_path)
    _seed_three(tmp_path)
    client = TestClient(create_app(tmp_path, require_auth=False))

    resp = client.get("/api/v1/posture/as-of", params={"as_of": "2026-04-15"})
    assert resp.status_code == HTTPStatus.OK
    body = resp.json()
    assert set(body) == {"data", "meta", "errors"}
    assert body["meta"]["resource"] == "posture.as_of"
    assert body["data"]["evaluated_at"] == "2026-03-01T00:00:00Z"

    missing = client.get("/api/v1/posture/as-of")
    assert missing.status_code == HTTPStatus.BAD_REQUEST
    assert missing.json()["errors"][0]["code"] == "bad_request"

    invalid = client.get("/api/v1/posture/as-of", params={"as_of": "nonsense"})
    assert invalid.status_code == HTTPStatus.BAD_REQUEST
    assert invalid.json()["errors"][0]["code"] == "bad_request"
