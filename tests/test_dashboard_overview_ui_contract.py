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

    assert 'title="Compliance"' in dashboard
    assert 'title="Operations"' in dashboard
    for label in ("Frameworks", "Control families", "Test results", "Findings", "Sources", "Exports"):
        assert f'label: "{label}"' in dashboard
    assert "assessment={data}" in dashboard
    assert "ingestion={ingestion.data}" in dashboard
    assert "Current assessment" in assessment
    assert "Control pass rate" in assessment
    assert "Open findings" in assessment
    assert "Assessment export" in assessment
    assert "Evidence loop" not in dashboard


def test_dashboard_framework_posture_uses_compact_two_row_tray() -> None:
    overview = (ROOT / "app/web/src/components/dashboard/ComplianceOverview.tsx").read_text(encoding="utf-8")

    assert "grid-rows-2" in overview
    assert "grid-flow-col" in overview
    assert "auto-cols-[104px]" in overview
    assert "h-[72px]" in overview
    assert "grid-cols-[30px_minmax(0,1fr)]" in overview
    assert "Framework families" in overview
    assert "catalog only" in overview
    assert "planned" in overview
    assert "overflow-x-auto" in overview
    assert 'aria-label="Framework posture comparison"' in overview
    assert ".slice(0, 6)" not in overview


def test_dashboard_kpis_are_flat_theme_tiles_and_pass_the_framework_catalog() -> None:
    dashboard = DASHBOARD.read_text(encoding="utf-8")
    assessment = ASSESSMENT.read_text(encoding="utf-8")

    assert "catalog={registeredFrameworks.data ?? []}" in dashboard
    assert "Evidence to refresh" in assessment
    assert "Needs evidence" in assessment
    # Flat tiles on surface/line tokens: no gradients, no hardcoded dark hexes.
    assert "text-white" not in assessment
    assert "radial-gradient" not in assessment
    assert "dark:border-slate" not in assessment
    assert not re.search(r"#[0-9a-fA-F]{3,6}\b", assessment)
    assert "border-line bg-surface" in assessment
    # rounded-2xl is outside the tokenized radius scale.
    assert "rounded-2xl" not in assessment
    assert "rounded-xl" in assessment


def test_assessment_status_and_details_are_accessible() -> None:
    assessment = ASSESSMENT.read_text(encoding="utf-8")

    assert re.search(r'<h2[^>]*className="sr-only"[^>]*>\s*Current assessment\s*</h2>', assessment)
    assert "<h2>{status}</h2>" not in assessment
    assert "formatDateTime(evaluatedAt)" in assessment
    assert "evaluatedAt={assessment.evaluated_at}" in assessment
    assert "toLocaleString" not in assessment
    assert "group relative" not in assessment
    assert "ChevronDown" in assessment
    assert "Escape" in assessment
    assert "pointerdown" in assessment
    assert 'href="/evidence"' in assessment
    assert 'href="/evidence/"' not in assessment
    # The legend is compact on mobile rather than hidden.
    assert "hidden flex-wrap" not in assessment


def test_dashboard_has_no_duplicate_lifecycle_or_overview_kpis() -> None:
    dashboard = DASHBOARD.read_text(encoding="utf-8")

    assert dashboard.count("<TrustLifecycle") == 1
    assert "Assessment hash" not in dashboard
    assert "Proof export" not in dashboard
    assert 'label="Framework posture"' not in dashboard
    assert "KpiTile" not in dashboard
    assert '{" "}' not in dashboard
    assert '<Badge tone="info">Open audit room</Badge>' not in dashboard
    assert '<Button asChild size="sm"' in dashboard
    assert "queries={tests}" in dashboard
    assert 'ROUTE_LABELS["/dashboard"]' in dashboard


def test_unused_dashboard_visuals_are_removed() -> None:
    for name in ("FrameworkBars", "PostureRing", "TrustSignalFlow"):
        assert not (DASHBOARD_DIR / f"{name}.tsx").exists(), name


def test_dashboard_readiness_cards_keep_framework_marks_legible() -> None:
    readiness = READINESS.read_text(encoding="utf-8")

    assert "size={40}" in readiness
    assert 'aria-label="Framework posture list"' in readiness


def test_next_dev_keeps_runtime_output_inside_the_web_project() -> None:
    config = NEXT_CONFIG.read_text(encoding="utf-8")

    assert 'distDir: isDev ? ".next"' in config
    assert '"../../src/security_lakehouse/web/dist"' in config
