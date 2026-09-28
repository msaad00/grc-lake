"""One definition of "framework pack" shared by the API, console, and README.

A registry entry with no seeded controls (a planned pack or a superseded
edition) is a stub: it is listed, but never counted as a framework pack.
"""

from __future__ import annotations

import json
from pathlib import Path

from security_lakehouse.framework_coverage import build_framework_coverage, framework_coverage_summary
from security_lakehouse.framework_provenance import (
    build_framework_view,
    framework_pack_counts,
    framework_pack_state,
)
from security_lakehouse.readiness import build_readiness_view

ROOT = Path(__file__).resolve().parents[1]


def _seeded_framework_ids() -> set[str]:
    catalog = json.loads((ROOT / "controls" / "catalog.json").read_text(encoding="utf-8"))
    return {control["framework_id"] for control in catalog["controls"]}


def test_pack_state_rule() -> None:
    assert framework_pack_state({"superseded_by": "x"}, 3) == "seeded"
    assert framework_pack_state({"superseded_by": "iso-27701-2025"}, 0) == "superseded"
    assert framework_pack_state({"superseded_by": None}, 0) == "planned"
    assert framework_pack_state({}, 0) == "planned"


def test_pack_counts_split_stubs_from_packs() -> None:
    counts = framework_pack_counts(["seeded", "seeded", "planned", "superseded"])
    assert counts == {
        "registered_framework_count": 4,
        "seeded_framework_count": 2,
        "planned_stub_framework_count": 1,
        "superseded_framework_count": 1,
        "stub_framework_count": 2,
    }
    assert framework_pack_counts([])["seeded_framework_count"] == 0


def test_registry_stubs_are_soc1_and_withdrawn_27701() -> None:
    view = {row["framework_id"]: row for row in build_framework_view()}
    assert view["iso-27701-2019"]["pack_state"] == "superseded"
    assert view["soc1"]["pack_state"] == "planned"
    seeded = {fid for fid, row in view.items() if row["pack_state"] == "seeded"}
    assert seeded == _seeded_framework_ids()


def test_coverage_summary_counts_only_seeded_packs() -> None:
    rows = build_framework_coverage()
    summary = framework_coverage_summary(rows, [])
    assert summary["seeded_framework_count"] == len(_seeded_framework_ids())
    assert summary["stub_framework_count"] == summary["framework_count"] - summary["seeded_framework_count"]
    assert summary["superseded_framework_count"] == 1
    by_id = {row["framework_id"]: row for row in rows}
    assert by_id["iso-27701-2019"]["pack_state"] == "superseded"
    assert by_id["iso-27701-2019"]["superseded_by"] == "iso-27701-2025"


def test_readiness_rows_carry_pack_state() -> None:
    rows = {row["framework_id"]: row for row in build_readiness_view()}
    assert rows["soc1"]["pack_state"] == "planned"
    assert rows["soc2"]["pack_state"] == "seeded"


def test_graph_has_a_node_only_for_seeded_packs(tmp_path: Path) -> None:
    from security_lakehouse.graph import build_compliance_graph

    graph = build_compliance_graph(tmp_path)
    framework_ids = {node["framework_id"] for node in graph["nodes"] if node["kind"] == "framework"}
    assert framework_ids == _seeded_framework_ids()


def test_readme_summary_uses_the_shared_count() -> None:
    import sys

    sys.path.insert(0, str(ROOT / "tools"))
    import render_readme_header

    summary = render_readme_header.render_readme_summary()
    assert summary.startswith(f"**{len(_seeded_framework_ids())} framework packs")
    assert "planned or superseded" in summary
