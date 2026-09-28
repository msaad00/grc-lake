"""Mapping review on the CLI and MCP: CLI can decide locally, MCP can only read."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from security_lakehouse.cli import main
from security_lakehouse.mapping_review import list_decisions
from security_lakehouse.safeguards import load_safeguards


def _proposed() -> dict[str, str]:
    for entry in load_safeguards()["safeguards"]:
        for member in entry["satisfies"]:
            if member.get("review_status") == "proposed":
                return {
                    "safeguard_id": entry["safeguard_id"],
                    "control_id": member["control_id"],
                    "framework_id": member["framework_id"],
                }
    raise AssertionError("no proposed mapping")


def _decide_args(lake: Path, verb: str, item: dict[str, str], *extra: str) -> list[str]:
    return [
        "frameworks",
        "review",
        verb,
        "--lake",
        str(lake),
        "--safeguard",
        item["safeguard_id"],
        "--framework",
        item["framework_id"],
        "--control",
        item["control_id"],
        *extra,
    ]


def test_cli_approve_requires_reviewer_and_rationale(tmp_path: Path, capsys) -> None:
    item = _proposed()
    with pytest.raises(SystemExit):
        main(_decide_args(tmp_path, "approve", item, "--rationale", "ok"))
    with pytest.raises(SystemExit):
        main(_decide_args(tmp_path, "approve", item, "--reviewer", "grc@acme.test"))
    assert list_decisions(tmp_path) == []


def test_cli_approve_reject_and_needs_changes_record_attributable_decisions(tmp_path: Path, capsys) -> None:
    item = _proposed()
    for verb, decision in (("approve", "approve"), ("needs-changes", "needs_changes"), ("reject", "reject")):
        code = main(
            _decide_args(
                tmp_path,
                verb,
                item,
                "--reviewer",
                "grc@acme.test",
                "--rationale",
                f"{verb} because",
                "--evidence-ref",
                "ticket GRC-12",
            )
        )
        assert code == 0
        out = json.loads(capsys.readouterr().out)
        assert out["decision"] == decision
    rows = list_decisions(tmp_path)
    assert [row["decision"] for row in rows] == ["approve", "needs_changes", "reject"]
    assert {row["auth_method"] for row in rows} == {"cli-local"}
    assert {row["reviewer"] for row in rows} == {"grc@acme.test"}
    assert rows[2]["supersedes"] == rows[1]["decision_id"]


def test_cli_rejects_unknown_mapping(tmp_path: Path, capsys) -> None:
    item = {**_proposed(), "control_id": "NOT-A-CONTROL"}
    code = main(_decide_args(tmp_path, "approve", item, "--reviewer", "a@b.test", "--rationale", "x"))
    assert code == 1
    assert "no shipped mapping" in capsys.readouterr().err
    assert list_decisions(tmp_path) == []


def test_cli_export_json_and_csv(tmp_path: Path, capsys) -> None:
    item = _proposed()
    main(_decide_args(tmp_path, "approve", item, "--reviewer", "grc@acme.test", "--rationale", "Confirmed, clause 4"))
    capsys.readouterr()
    assert main(["frameworks", "review", "export", "--lake", str(tmp_path)]) == 0
    exported = json.loads(capsys.readouterr().out)
    assert exported["decision_log"]["ok"] is True
    assert exported["decision_log"]["length"] == 1
    assert exported["decisions"][0]["reviewer"] == "grc@acme.test"

    out = tmp_path / "decisions.csv"
    assert main(["frameworks", "review", "export", "--lake", str(tmp_path), "--format", "csv", "--out", str(out)]) == 0
    rows = list(csv.DictReader(io.StringIO(out.read_text(encoding="utf-8"))))
    assert rows[0]["control_id"] == item["control_id"]
    assert rows[0]["rationale"] == "Confirmed, clause 4"
    assert rows[0]["record_hash"]


def test_cli_safeguards_and_coverage_show_org_review_separately(tmp_path: Path, capsys) -> None:
    item = _proposed()
    main(_decide_args(tmp_path, "approve", item, "--reviewer", "grc@acme.test", "--rationale", "ok"))
    capsys.readouterr()
    assert main(["frameworks", "safeguards", "--lake", str(tmp_path)]) == 0
    coverage = json.loads(capsys.readouterr().out)
    assert coverage["org_reviewed_mappings"] == 1
    assert main(["frameworks", "safeguards", "--lake", str(tmp_path), "--format", "table"]) == 0
    table = capsys.readouterr().out
    assert "maintainer-reviewed" in table and "org-reviewed" in table and "rejected" in table
    assert main(["frameworks", "coverage", "--lake", str(tmp_path)]) == 0
    ledger = json.loads(capsys.readouterr().out)
    assert ledger["summary"]["org_reviewed_mapping_count"] == 1
    # Without a lake the shipped numbers are unchanged.
    assert main(["frameworks", "safeguards"]) == 0
    assert json.loads(capsys.readouterr().out)["org_reviewed_mappings"] == 0


def test_cli_review_queue_and_oscal_read_the_lake(tmp_path: Path, capsys) -> None:
    item = _proposed()
    main(_decide_args(tmp_path, "approve", item, "--reviewer", "grc@acme.test", "--rationale", "ok"))
    capsys.readouterr()
    assert main(["frameworks", "review-queue", "--lake", str(tmp_path), "--framework", item["framework_id"]]) == 0
    queue = json.loads(capsys.readouterr().out)
    assert (item["safeguard_id"], item["control_id"]) not in {
        (i["safeguard_id"], i["control_id"]) for i in queue["items"]
    }
    out = tmp_path / "cd.json"
    assert main(["oscal", "export", "--component-definition", "--lake", str(tmp_path), "--out", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    reviewers = [
        prop["value"]
        for component in doc["component-definition"]["components"]
        for impl in component.get("control-implementations", [])
        for req in impl["implemented-requirements"]
        for prop in req["props"]
        if prop["name"] == "trustops-reviewed-by"
    ]
    assert reviewers == ["grc@acme.test"]


# --- MCP: read-only ------------------------------------------------------------------


def test_mcp_can_list_the_queue_and_decisions_but_has_no_decision_tool(tmp_path: Path) -> None:
    pytest.importorskip("mcp")
    from security_lakehouse import mcp_server
    from test_mcp_server import call_tool, tool_names

    item = _proposed()
    main(_decide_args(tmp_path, "approve", item, "--reviewer", "grc@acme.test", "--rationale", "ok"))
    server = mcp_server.build_server(tmp_path)
    names = tool_names(server)
    review_tools = {name for name in names if "mapping_review" in name}
    assert review_tools == {"get_mapping_review_queue", "list_mapping_review_decisions"}
    assert not {
        name
        for name in names
        if "mapping" in name and any(v in name for v in ("approve", "reject", "decide", "record"))
    }

    queue = call_tool(server, "get_mapping_review_queue", framework_id=item["framework_id"])
    assert (item["safeguard_id"], item["control_id"]) not in {
        (i["safeguard_id"], i["control_id"]) for i in queue["items"]
    }
    decisions = call_tool(server, "list_mapping_review_decisions")
    assert decisions["decisions"][0]["reviewer"] == "grc@acme.test"
    coverage = call_tool(server, "get_framework_coverage")
    assert coverage["summary"]["org_reviewed_mapping_count"] == 1
