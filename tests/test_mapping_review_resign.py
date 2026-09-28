"""Re-signing the mapping-review log tip after a signing-key rotation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_lakehouse import mapping_review
from security_lakehouse.audit_log import build_audit_log
from security_lakehouse.cli import main
from security_lakehouse.ledger import canonical_record_hash
from security_lakehouse.mapping_review import (
    MappingReviewError,
    effective_safeguards,
    record_decisions,
    resign_review_tip,
    review_audit_path,
    review_log_path,
    review_tip_path,
    verify_review_log,
)
from security_lakehouse.safeguards import load_safeguards

OLD_KEY = "old-signing-key-" + "o" * 32
NEW_KEY = "new-signing-key-" + "n" * 32


def _proposed_items(count: int) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for entry in load_safeguards()["safeguards"]:
        for member in entry["satisfies"]:
            if member.get("review_status") == "proposed":
                items.append(
                    {
                        "safeguard_id": entry["safeguard_id"],
                        "control_id": member["control_id"],
                        "framework_id": member["framework_id"],
                    }
                )
                if len(items) == count:
                    return items
    raise AssertionError("not enough proposed mappings shipped")


def _decide(lake: Path, item: dict[str, str]) -> None:
    record_decisions(lake, items=[item], decision="approve", rationale="Evidence matches.", reviewer="grc@acme.test")


@pytest.fixture
def rotated_lake(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A log signed with OLD_KEY, then the server key rotated to NEW_KEY."""
    monkeypatch.setenv(mapping_review.SIGNING_KEY_ENV, OLD_KEY)
    first, second = _proposed_items(2)
    _decide(tmp_path, first)
    _decide(tmp_path, second)
    assert verify_review_log(tmp_path)["tip_mac"] == "verified"
    monkeypatch.setenv(mapping_review.SIGNING_KEY_ENV, NEW_KEY)
    assert verify_review_log(tmp_path)["tip_mac"] == "invalid"
    return tmp_path


def test_resign_restores_a_rotated_log_and_records_an_audit_entry(rotated_lake: Path) -> None:
    result = resign_review_tip(rotated_lake, previous_key=OLD_KEY, actor="ops@acme.test")

    log = verify_review_log(rotated_lake)
    assert log["ok"] is True and log["tip_mac"] == "verified"
    assert result["status"] == "resigned"
    assert result["length"] == 2 and result["tip_hash"] == log["tip_hash"]
    assert effective_safeguards(rotated_lake)["review_log_verified"] is True
    # New decisions are accepted again and signed with the new key.
    _decide(rotated_lake, _proposed_items(3)[2])
    assert verify_review_log(rotated_lake)["tip_mac"] == "verified"

    rows = [json.loads(line) for line in review_audit_path(rotated_lake).read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1
    audit = rows[0]
    assert audit["event"] == "tip_resigned"
    assert audit["actor"] == "ops@acme.test"
    assert audit["log_length"] == 2 and audit["tip_hash"] == log["tip_hash"]
    assert audit["record_hash"] == canonical_record_hash(audit)
    assert OLD_KEY not in json.dumps(audit) and NEW_KEY not in json.dumps(audit)


def test_resign_is_listed_in_the_workbench_audit_log(rotated_lake: Path) -> None:
    resign_review_tip(rotated_lake, previous_key=OLD_KEY, actor="ops@acme.test")
    entries = build_audit_log(rotated_lake, category="mapping_review")
    assert len(entries) == 1
    assert entries[0]["actor"] == "ops@acme.test"
    assert entries[0]["result"] == "resigned"
    assert "re-signed" in entries[0]["summary"]


def _unchanged(lake: Path, sidecar: str) -> None:
    assert review_tip_path(lake).read_text(encoding="utf-8") == sidecar
    assert not review_audit_path(lake).exists()
    assert verify_review_log(lake)["tip_mac"] == "invalid"


def test_resign_refuses_the_wrong_previous_key(rotated_lake: Path) -> None:
    sidecar = review_tip_path(rotated_lake).read_text(encoding="utf-8")
    with pytest.raises(MappingReviewError, match="previous key"):
        resign_review_tip(rotated_lake, previous_key="not-the-old-key", actor="ops")
    _unchanged(rotated_lake, sidecar)


def test_resign_refuses_a_broken_chain(rotated_lake: Path) -> None:
    path = review_log_path(rotated_lake)
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[0]["decision"] = "reject"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    sidecar = review_tip_path(rotated_lake).read_text(encoding="utf-8")
    with pytest.raises(MappingReviewError, match="hash chain"):
        resign_review_tip(rotated_lake, previous_key=OLD_KEY, actor="ops")
    assert review_tip_path(rotated_lake).read_text(encoding="utf-8") == sidecar
    assert not review_audit_path(rotated_lake).exists()


def test_resign_cannot_launder_a_consistently_rewritten_chain(rotated_lake: Path) -> None:
    # Someone with lake write access but no key rewrites a decision and
    # recomputes every hash: the chain verifies, the old MAC does not.
    path = review_log_path(rotated_lake)
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    prev = None
    for row in rows:
        if row is rows[0]:
            row["decision"] = "reject"
        row["prev_hash"] = prev
        row["record_hash"] = canonical_record_hash(row)
        prev = row["record_hash"]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    sidecar = review_tip_path(rotated_lake).read_text(encoding="utf-8")
    with pytest.raises(MappingReviewError, match="previous key"):
        resign_review_tip(rotated_lake, previous_key=OLD_KEY, actor="ops")
    _unchanged(rotated_lake, sidecar)


def test_resign_refuses_a_missing_sidecar(rotated_lake: Path) -> None:
    review_tip_path(rotated_lake).unlink()
    with pytest.raises(MappingReviewError, match="sidecar"):
        resign_review_tip(rotated_lake, previous_key=OLD_KEY, actor="ops")
    assert not review_tip_path(rotated_lake).exists()
    assert not review_audit_path(rotated_lake).exists()


def test_resign_requires_a_current_key(rotated_lake: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(mapping_review.SIGNING_KEY_ENV)
    with pytest.raises(MappingReviewError, match=mapping_review.SIGNING_KEY_ENV):
        resign_review_tip(rotated_lake, previous_key=OLD_KEY, actor="ops")


def test_resign_is_a_no_op_when_the_tip_already_verifies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(mapping_review.SIGNING_KEY_ENV, NEW_KEY)
    _decide(tmp_path, _proposed_items(1)[0])
    sidecar = review_tip_path(tmp_path).read_text(encoding="utf-8")
    result = resign_review_tip(tmp_path, previous_key=OLD_KEY, actor="ops")
    assert result["status"] == "already_current"
    assert review_tip_path(tmp_path).read_text(encoding="utf-8") == sidecar
    assert not review_audit_path(tmp_path).exists()


def test_resign_refuses_an_empty_previous_key(rotated_lake: Path) -> None:
    with pytest.raises(MappingReviewError, match="previous key"):
        resign_review_tip(rotated_lake, previous_key="  ", actor="ops")


# --- CLI -----------------------------------------------------------------------


def test_cli_resign_reads_the_previous_key_from_the_named_env(
    rotated_lake: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setenv("OLD_TRUSTOPS_KEY", OLD_KEY)
    code = main(
        [
            "frameworks",
            "review",
            "resign",
            "--lake",
            str(rotated_lake),
            "--previous-key-env",
            "OLD_TRUSTOPS_KEY",
            "--actor",
            "ops@acme.test",
        ]
    )
    out = capsys.readouterr()
    assert code == 0, out.err
    payload = json.loads(out.out)
    assert payload["status"] == "resigned"
    assert payload["decision_log"]["tip_mac"] == "verified"
    assert OLD_KEY not in out.out + out.err
    assert verify_review_log(rotated_lake)["ok"] is True


def test_cli_resign_fails_without_the_previous_key(rotated_lake: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.delenv("OLD_TRUSTOPS_KEY", raising=False)
    code = main(
        ["frameworks", "review", "resign", "--lake", str(rotated_lake), "--previous-key-env", "OLD_TRUSTOPS_KEY"]
    )
    err = capsys.readouterr().err
    assert code == 1
    assert "OLD_TRUSTOPS_KEY" in err
    assert verify_review_log(rotated_lake)["tip_mac"] == "invalid"


def test_cli_resign_fails_with_the_wrong_previous_key(
    rotated_lake: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setenv("OLD_TRUSTOPS_KEY", "wrong")
    code = main(
        ["frameworks", "review", "resign", "--lake", str(rotated_lake), "--previous-key-env", "OLD_TRUSTOPS_KEY"]
    )
    assert code == 1
    assert "previous key" in capsys.readouterr().err
    assert not review_audit_path(rotated_lake).exists()
