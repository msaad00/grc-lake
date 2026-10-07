"""Demo provenance is explicit, survives normalization, and never implies all rows are synthetic."""

import pytest

from security_lakehouse.assessment import build_current_posture
from security_lakehouse.io import write_jsonl


@pytest.mark.parametrize(
    ("rows", "expected"),
    [
        ([{"source": "github", "attributes": {"demo": True, "fixture": "golden"}}], True),
        ([{"source": "github", "attributes": {"demo": False}}], False),
        ([{"source": "github"}, {"source": "github", "attributes": {"demo": True}}], True),
        ([{"source": "golden", "attributes": {"demo": "true"}}], False),
        ([{"source": "synthetic-audit-fixture"}], True),
    ],
)
def test_assessment_declares_any_explicit_synthetic_evidence(tmp_path, rows, expected):
    write_jsonl(tmp_path / "bronze/raw_events.jsonl", [{"raw": row} for row in rows])
    assert build_current_posture(tmp_path)["synthetic_fixture"] is expected


def test_provenance_updates_after_new_bronze_bytes(tmp_path):
    path = tmp_path / "bronze/raw_events.jsonl"
    write_jsonl(path, [{"raw": {"source": "github"}}])
    assert build_current_posture(tmp_path)["synthetic_fixture"] is False
    write_jsonl(path, [{"raw": {"source": "github", "attributes": {"demo": True}}}])
    assert build_current_posture(tmp_path)["synthetic_fixture"] is True
    write_jsonl(path, [{"raw": {"source": "github"}}])
    assert build_current_posture(tmp_path)["synthetic_fixture"] is False


def test_same_metadata_cannot_hide_a_changed_synthetic_marker(tmp_path, monkeypatch):
    from pathlib import Path

    from security_lakehouse.evidence_provenance import contains_synthetic_evidence

    path = (tmp_path / "bronze/raw_events.jsonl").resolve()
    write_jsonl(path, [{"raw": {"attributes": {"demo": False, "pad": "x"}}}])
    original_stat = path.stat()
    stat = Path.stat
    # Simulate identical filesystem metadata: display provenance must depend on
    # current bytes, even when an external copy preserves source timestamps.
    monkeypatch.setattr(Path, "stat", lambda self, *a, **k: original_stat if self == path else stat(self, *a, **k))
    assert contains_synthetic_evidence(tmp_path) is False
    write_jsonl(path, [{"raw": {"attributes": {"demo": True, "pad": "xx"}}}])
    assert stat(path).st_size == original_stat.st_size
    assert contains_synthetic_evidence(tmp_path) is True
