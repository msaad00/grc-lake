"""Framework coverage should be scannable before operators open every card."""

from pathlib import Path

ROOT = Path(__file__).parents[1]
PAGE = ROOT / "app/web/src/app/frameworks/page.tsx"
ROSTER = ROOT / "app/web/src/components/framework/FrameworkRoster.tsx"


def test_frameworks_page_renders_the_marked_roster() -> None:
    page = PAGE.read_text(encoding="utf-8")
    roster = ROSTER.read_text(encoding="utf-8")

    assert "FrameworkRoster" in page
    assert "<FrameworkRoster" in page
    assert "FrameworkBadge" in roster
    assert "FrameworkView" in roster
    assert "FrameworkCoverageRow" in roster
    assert "FrameworkReadiness" in roster


def test_framework_roster_separates_readiness_from_unavailable_evaluation() -> None:
    roster = ROSTER.read_text(encoding="utf-8")

    assert "Framework roster" in roster
    assert "Readiness tracked" in roster
    assert "Not evaluated" in roster
    assert "${formatCount(mapped)}/${formatCount(total)} controls mapped" in roster
    assert "${formatCount(attestable)} fully reviewed" in roster
