"""Regression contract for a compact, source-aligned dashboard overview."""

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
DASHBOARD = ROOT / "app/web/src/app/dashboard/page.tsx"
ASSESSMENT = ROOT / "app/web/src/components/dashboard/AssessmentOverview.tsx"
READINESS = ROOT / "app/web/src/components/dashboard/ReadinessGrid.tsx"
DASHBOARD_DIR = ROOT / "app/web/src/components/dashboard"
NEXT_CONFIG = ROOT / "app/web/next.config.ts"


def test_dashboard_overview_is_source_aligned_and_tabbed() -> None:
    dashboard = DASHBOARD.read_text(encoding="utf-8")
    assessment = ASSESSMENT.read_text(encoding="utf-8")

    assert 'title="Framework coverage"' in dashboard
    assert 'title="Priority actions"' in dashboard
    for label in ("Frameworks", "Control families", "Test results", "Findings", "Sources"):
        assert f'label: "{label}"' in dashboard
    # Export status is shown once, in the header status line.
    assert 'label: "Exports"' not in dashboard
    assert "assessment={data}" in dashboard
    assert "ingestion={ingestion.data}" in dashboard
    assert "Latest lake assessment" in assessment
    assert "Control pass rate" in assessment
    assert "Open findings" in assessment
    assert "Assessment export" in assessment
    assert "Evidence loop" not in dashboard


def test_dashboard_has_no_duplicate_framework_tray_or_detail_section() -> None:
    dashboard = DASHBOARD.read_text(encoding="utf-8")

    for name in ("ComplianceOverview", "DashboardStripsRow", "EvidenceTrend", "DataPipelineStrip", "TrustLifecycle"):
        assert name not in dashboard, name
        assert not (DASHBOARD_DIR / f"{name}.tsx").exists(), name
    assert "Operational detail" not in dashboard


def test_dashboard_lists_are_concise_and_never_clip() -> None:
    readiness = READINESS.read_text(encoding="utf-8")
    fix_next = (DASHBOARD_DIR / "FixNext.tsx").read_text(encoding="utf-8")

    # One sort control and one expander; no Priority/All filter or summary line.
    assert "<select" in readiness
    assert "Priority" not in readiness
    assert "insufficient coverage`" not in readiness
    assert "need fresh evidence" not in readiness
    # Findings preview: severity, title, control ID; context lives in the drawer.
    assert "const PREVIEW = 5" in fix_next
    assert "overflow-y-auto" not in fix_next
    for field in ("asset_owner", "environment", "v.source"):
        assert field not in fix_next, field
    assert "View all findings" in fix_next


def test_dashboard_kpis_are_flat_theme_tiles_and_pass_the_framework_catalog() -> None:
    dashboard = DASHBOARD.read_text(encoding="utf-8")
    assessment = ASSESSMENT.read_text(encoding="utf-8")

    assert "catalog={registeredFrameworks.data ?? []}" in dashboard
    assert "Evidence to refresh" in assessment
    assert "need evidence" in assessment
    # Flat tiles on surface/line tokens: no gradients, no hardcoded dark hexes.
    assert "text-white" not in assessment
    assert "radial-gradient" not in assessment
    assert "dark:border-slate" not in assessment
    assert not re.search(r"#[0-9a-fA-F]{3,6}\b", assessment)
    assert "border-line bg-surface" in assessment
    # rounded-2xl is outside the tokenized radius scale.
    assert "rounded-2xl" not in assessment
    assert "rounded-lg" in assessment
    # Tiles: label, number, one context line, optional meter; no icons.
    assert "lucide-react" not in assessment.split("function Tile")[1].split("function EvaluatedDetails")[0]
    assert "StackedBar" not in assessment


def test_assessment_status_and_details_are_accessible() -> None:
    assessment = ASSESSMENT.read_text(encoding="utf-8")

    assert re.search(r'<h2[^>]*className="sr-only"[^>]*>\s*Latest lake assessment\s*</h2>', assessment)
    assert "<h2>{status}</h2>" not in assessment
    assert "formatDateTime(evaluatedAt)" in assessment
    assert "evaluatedAt={assessment.evaluated_at}" in assessment
    assert "toLocaleString" not in assessment
    assert "group relative" not in assessment
    assert "ChevronDown" in assessment
    assert "assessment details" in assessment
    assert "Escape" in assessment
    assert "pointerdown" in assessment
    assert 'href="/evidence"' in assessment
    assert 'href="/evidence/"' not in assessment
    # The legend is compact on mobile rather than hidden.
    assert "hidden flex-wrap" not in assessment


def test_dashboard_has_no_duplicate_lifecycle_or_overview_kpis() -> None:
    dashboard = DASHBOARD.read_text(encoding="utf-8")

    assert "<TrustLifecycle" not in dashboard
    assert "Assessment hash" not in dashboard
    assert "Proof export" not in dashboard
    assert 'label="Framework posture"' not in dashboard
    assert "KpiTile" not in dashboard
    assert '{" "}' not in dashboard
    assert '<Badge tone="info">Open audit room</Badge>' not in dashboard
    assert "queries={tests}" in dashboard
    assert 'ROUTE_LABELS["/dashboard"]' in dashboard


def test_unused_dashboard_visuals_are_removed() -> None:
    for name in ("FrameworkBars", "PostureRing", "TrustSignalFlow"):
        assert not (DASHBOARD_DIR / f"{name}.tsx").exists(), name


def test_dashboard_readiness_cards_keep_framework_marks_legible() -> None:
    readiness = READINESS.read_text(encoding="utf-8")

    assert "size={32}" in readiness
    assert 'aria-label="Framework posture list"' in readiness


def test_next_dev_keeps_runtime_output_inside_the_web_project() -> None:
    config = NEXT_CONFIG.read_text(encoding="utf-8")

    assert 'distDir: isDev ? ".next"' in config
    assert '"../../src/security_lakehouse/web/dist"' in config
