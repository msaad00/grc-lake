"""Contracts for consistent trust-loop language across core console pages."""

from pathlib import Path

ROOT = Path(__file__).parents[1]
COMPONENT = ROOT / "app/web/src/components/TrustPipelineStrip.tsx"
CONTROLS = ROOT / "app/web/src/app/controls/page.tsx"
FRAMEWORKS = ROOT / "app/web/src/app/frameworks/page.tsx"
VIOLATIONS = ROOT / "app/web/src/app/violations/page.tsx"
AUDIT_ROOM = ROOT / "app/web/src/app/audit-room/page.tsx"
CLOUD_PANEL = ROOT / "app/web/src/components/connectors/CloudLinkPanel.tsx"


def test_core_pages_share_the_trust_pipeline_strip() -> None:
    component = COMPONENT.read_text(encoding="utf-8")
    controls = CONTROLS.read_text(encoding="utf-8")
    frameworks = FRAMEWORKS.read_text(encoding="utf-8")
    violations = VIOLATIONS.read_text(encoding="utf-8")
    audit_room = AUDIT_ROOM.read_text(encoding="utf-8")

    assert "TrustPipelineStrip" in component
    assert "Framework map" in component
    assert "Evidence facts" in component
    assert "Control eval" in component
    assert "Findings" in component
    assert "Proof export" in component
    assert 'aria-current={active ? "page" : undefined}' in component
    assert 'href: "/audit-room"' in component

    assert 'activeStage="controls"' in controls
    assert 'activeStage="frameworks"' in frameworks
    assert 'activeStage="findings"' in violations
    assert 'aria-label="Audit room view"' in audit_room
    assert '<TrustPipelineStrip activeStage="proof" />' not in audit_room


def test_cloud_link_panel_reinforces_read_only_no_key_paths() -> None:
    panel = CLOUD_PANEL.read_text(encoding="utf-8")

    assert "Read-only access" in panel
    assert "No long-lived keys" in panel
    assert "GRC Lake verifies STS assume-role after deployment." in panel
    assert "Deployment method" in panel
