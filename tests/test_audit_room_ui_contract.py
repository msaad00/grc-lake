"""Regression contract for a compact audit-room proof workspace."""

from pathlib import Path

ROOT = Path(__file__).parents[1]
PAGE = ROOT / "app/web/src/app/audit-room/page.tsx"


def test_audit_room_uses_compact_tabbed_workspace() -> None:
    page = PAGE.read_text(encoding="utf-8")

    assert "const AUDIT_ROOM_TABS" in page
    assert '"Freshness", "Runs", "Snapshots", "Gaps"' in page
    assert 'useState<AuditRoomTab>("Freshness")' in page
    assert 'aria-label="Audit room view"' in page
    assert "activeAuditTab ===" in page
    assert "Readiness summary" in page
    assert "EvidenceFreshnessSlaPanel" in page
    assert "IngestionLoopStrip" in page
    assert "AuditSnapshotTimeline" in page
    assert "Blocking gaps" in page


def test_audit_room_does_not_render_every_audit_surface_by_default() -> None:
    page = PAGE.read_text(encoding="utf-8")

    assert "<TrustPipelineStrip" not in page
    assert "<EvidenceFreshnessSlaPanel />" not in page
    assert "<IngestionLoopStrip />" not in page
    assert "<AuditRoomTrendsPanel />" not in page
    assert "<RemediationSlaStrip />" not in page
    assert "<AuditSnapshotTimeline />" not in page
    assert "Audit workflow checklist" not in page
    assert "Extended audit programs" not in page


def test_audit_room_does_not_present_product_features_as_readiness() -> None:
    page = PAGE.read_text(encoding="utf-8")

    assert "workflow_coverage" not in page
    assert '"shipped"' not in page


def test_scores_have_one_name_and_definition_across_pages() -> None:
    """Overview and audit room read score names from SCORE_COPY; no ad-hoc labels."""
    web = ROOT / "app/web/src"
    page = PAGE.read_text(encoding="utf-8")
    overview = (web / "components/dashboard/AssessmentOverview.tsx").read_text(encoding="utf-8")
    copy = (web / "lib/console-copy.ts").read_text(encoding="utf-8")

    assert "export const SCORE_COPY" in copy
    assert "SCORE_COPY.auditReadiness.label" in page
    assert "SCORE_COPY.auditReadiness.definition" in page
    assert "SCORE_COPY.assessment.label" in page
    assert "SCORE_COPY.assessment.label" in overview
    for stale in ('label="Audit score"', "weighted posture", "% posture"):
        assert stale not in page, stale


def test_freshness_panel_does_not_repeat_the_summary_kpis() -> None:
    panel = (ROOT / "app/web/src/components/evidence/EvidenceFreshnessSlaPanel.tsx").read_text(encoding="utf-8")
    # Fresh rate and SLA breaches are already in the readiness summary row.
    assert "Fresh rate" not in panel
    assert "SLA breaches\n" not in panel
    assert "uppercase" not in panel
    assert 'replaceAll("_", " ")' not in panel
