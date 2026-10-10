"""The console must explain loading instead of rendering an empty canvas."""

from pathlib import Path

ROOT = Path(__file__).parents[1]
QUERY_STATE = ROOT / "app/web/src/components/QueryState.tsx"
BRAND = ROOT / "app/web/src/lib/brand.ts"
TOP_BAR = ROOT / "app/web/src/components/shell/TopBar.tsx"
LOGO = ROOT / "app/web/src/components/brand/GrcLakeLogo.tsx"


def test_loading_state_is_visible_and_branded() -> None:
    source = QUERY_STATE.read_text(encoding="utf-8")

    assert "GrcLakeMark" in source
    assert 'role="status"' in source
    assert "Loading" in source
    assert "Reading GRC Lake evidence" in source


def test_shell_uses_current_product_identity() -> None:
    brand = BRAND.read_text(encoding="utf-8")
    top_bar = TOP_BAR.read_text(encoding="utf-8")

    assert 'name: "GRC Lake"' in brand
    assert "Open, self-hosted GRC for cloud and AI" in brand
    assert "<GrcLakeLogo" in top_bar
    assert "showWordmark" in top_bar
    assert "BRAND.name" in LOGO.read_text(encoding="utf-8")
