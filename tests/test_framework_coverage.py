from __future__ import annotations

import json

from security_lakehouse.catalog import load_control_catalog, load_framework_registry
from security_lakehouse.cli import main
from security_lakehouse.framework_coverage import (
    build_control_asset_applicability,
    build_framework_coverage,
    framework_coverage_summary,
    render_framework_coverage_markdown,
)


def test_framework_coverage_ledger_counts_seeded_mappings(capsys) -> None:
    rows = build_framework_coverage()
    applicability = build_control_asset_applicability()
    summary = framework_coverage_summary(rows, applicability)
    implemented = [row for row in rows if row["implementation_status"] != "planned"]
    planned = [row for row in rows if row["implementation_status"] == "planned"]
    seeded_controls = load_control_catalog()

    assert summary["framework_count"] == len(load_framework_registry())
    assert summary["implemented_framework_count"] == len(implemented)
    assert summary["planned_framework_count"] == len(planned)
    assert summary["seeded_control_count"] == len(seeded_controls)
    assert summary["seeded_control_count"] >= 741
    assert summary["source_cited_mapping_count"] == len(seeded_controls)
    # Source-reconciled identifier mappings (CSF 2.0, NIST 800-53, RMF, CIS
    # Controls) are proposed, so they are cited but not reviewed.
    assert 0 < summary["reviewed_mapping_count"] < summary["source_cited_mapping_count"]
    rows_by_id = {row["framework_id"]: row for row in rows}
    assert rows_by_id["nist-800-53-rev5"]["reviewed_mapping_count"] == 0
    assert rows_by_id["soc2"]["reviewed_mapping_count"] == rows_by_id["soc2"]["seeded_control_count"]
    assert summary["missing_mapping_count"] == 0
    assert summary["seeded_mapping_coverage_pct"] == 100.0
    assert summary["asset_type_count"] == 20
    assert summary["control_asset_applicability_link_count"] == sum(
        row["applicable_control_count"] for row in applicability
    )
    assert summary["official_logo_count"] == 0
    assert summary["certification_seal_count"] == 0
    assert all(row["asset_policy"].startswith("neutral label") for row in rows)
    assert applicability[0]["asset_type"] == "service"
    assert applicability[0]["applicable_control_count"] >= 580

    assert main(["frameworks", "coverage"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["summary"] == summary
    assert out["applicability"] == applicability


def test_framework_coverage_markdown_is_source_linked_not_logo_based() -> None:
    applicability = build_control_asset_applicability()
    summary = framework_coverage_summary(build_framework_coverage(), applicability)
    markdown = render_framework_coverage_markdown(build_framework_coverage(), applicability)

    # Honest coverage lines, not a single conflated "100%" claim.
    assert f"Requirements catalogued: {summary['seeded_control_count']} (all source-cited)" in markdown
    assert "Mapped (touched by a safeguard):" in markdown
    assert "Reviewed safeguard mappings:" in markdown
    assert "Reviewed mappings |" in markdown  # the matrix column header
    assert "Asset types modeled: 20" in markdown
    assert "## Control-To-Asset Applicability" in markdown
    assert f"| `service` | {applicability[0]['applicable_control_count']} |" in markdown
    assert "Official source" in markdown
    assert "official logo" not in markdown.lower()
    assert "certification seal" not in markdown.lower()
    assert "EUR-Lex - Regulation (EU) 2016/679" in markdown


def test_attestable_coverage_is_honest_and_bounded() -> None:
    """Reviewed mapping coverage measures curation, not operating effectiveness.

    It must never exceed evaluatable (touched by any safeguard), which must
    never exceed the seeded requirement count. Source-citation coverage
    (`source_cited_mapping_count`, always 100%) is a different, weaker claim and must
    not be conflated with attestable coverage.
    """
    from security_lakehouse.framework_coverage import build_framework_coverage, framework_coverage_summary
    from security_lakehouse.safeguards import safeguards_by_requirement

    rows = build_framework_coverage()
    summary = framework_coverage_summary(rows)

    for row in rows:
        seeded = int(row["seeded_control_count"])
        evaluatable = int(row["evaluatable_requirement_count"])
        attestable = int(row["attestable_requirement_count"])
        assert 0 <= attestable <= evaluatable <= seeded, row["framework_id"]
        assert row["attestable_coverage_pct"] <= row["evaluatable_coverage_pct"] + 1e-9

    # Summary aggregates match and preserve the ordering.
    assert summary["attestable_requirement_count"] <= summary["evaluatable_requirement_count"]
    assert summary["evaluatable_requirement_count"] <= summary["seeded_control_count"]
    # There is a real review backlog today: broadly evaluatable, thinly attestable.
    assert summary["attestable_requirement_count"] < summary["evaluatable_requirement_count"]
    assert summary["attestable_requirement_count"] > 0

    # Honesty guard: attestable is derived from reviewed_only mappings, never the
    # broader touched set — so it can only grow as a human reviews mappings.
    reviewed = set(safeguards_by_requirement(reviewed_only=True))
    touched = set(safeguards_by_requirement())
    assert reviewed <= touched
    assert len(reviewed) == summary["attestable_requirement_count"] or reviewed != touched


def test_committed_coverage_doc_matches_generator() -> None:
    """docs/FRAMEWORK_COVERAGE.md must equal the generator (regenerate: make coverage-doc)."""
    import pathlib

    from security_lakehouse.framework_coverage import render_framework_coverage_doc

    committed = pathlib.Path("docs/FRAMEWORK_COVERAGE.md").read_text()
    assert committed == render_framework_coverage_doc(), "run `make coverage-doc` and commit"


def test_mcp_framework_coverage_tool_reports_attestable() -> None:
    """The MCP tool gives agents the same honest attestable ledger as the CLI."""
    import inspect

    from security_lakehouse import mcp_server

    src = inspect.getsource(mcp_server)
    assert "def get_framework_coverage" in src
    from security_lakehouse.framework_coverage import build_framework_coverage, framework_coverage_summary

    payload = {
        "summary": framework_coverage_summary(build_framework_coverage()),
        "frameworks": build_framework_coverage(),
    }
    assert "attestable_requirement_count" in payload["summary"]
    assert payload["summary"]["attestable_requirement_count"] <= payload["summary"]["evaluatable_requirement_count"]
