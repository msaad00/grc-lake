"""Regression contract for a compact, source-aligned dashboard overview."""

from pathlib import Path

ROOT = Path(__file__).parents[1]
DASHBOARD = ROOT / "app/web/src/app/dashboard/page.tsx"
ASSESSMENT = ROOT / "app/web/src/components/dashboard/AssessmentOverview.tsx"
READINESS = ROOT / "app/web/src/components/dashboard/ReadinessGrid.tsx"
SIGNAL_FLOW = ROOT / "app/web/src/components/dashboard/TrustSignalFlow.tsx"
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
    assert "Stale evidence" in assessment
    assert "Needs evidence" in assessment
    for hardcoded in ("bg-[radial-gradient", "text-white", "border-slate-700"):
        assert hardcoded not in assessment


def test_dashboard_readiness_cards_keep_framework_marks_legible() -> None:
    readiness = READINESS.read_text(encoding="utf-8")

    assert "size={40}" in readiness
    assert 'aria-label="Framework posture list"' in readiness


def test_dashboard_evidence_loop_keeps_stage_labels_readable() -> None:
    signal_flow = SIGNAL_FLOW.read_text(encoding="utf-8")

    assert 'aria-label="Evidence operating loop"' in signal_flow
    assert 'text-slate-300">' in signal_flow
    assert "font-medium text-slate-300" in signal_flow


def test_next_dev_keeps_runtime_output_inside_the_web_project() -> None:
    config = NEXT_CONFIG.read_text(encoding="utf-8")

    assert 'distDir: isDev ? ".next"' in config
    assert '"../../src/security_lakehouse/web/dist"' in config
