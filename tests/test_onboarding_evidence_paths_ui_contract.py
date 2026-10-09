"""Contract for explaining both supported evidence-entry paths during setup."""

from pathlib import Path

ROOT = Path(__file__).parents[1]
PAGE = ROOT / "app/web/src/app/onboarding/page.tsx"
COMPONENT = ROOT / "app/web/src/components/onboarding/OnboardingEvidencePaths.tsx"


def test_onboarding_explains_connector_first_and_lake_first_paths() -> None:
    page = PAGE.read_text(encoding="utf-8")
    component = COMPONENT.read_text(encoding="utf-8")

    assert "OnboardingEvidencePaths" in page
    assert "Choose how evidence enters GRC Lake" in component
    assert "Connect sources directly" in component
    assert "Bring an existing lake" in component
    assert "same normalized evidence" in component
    assert "No local paths or raw secrets are accepted in the console" in component
    assert "/connectors/?onboarding=1" in component
    assert "snowflake-evidence-lake" in component
