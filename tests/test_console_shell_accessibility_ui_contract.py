"""Regression contract for an accessible, consistently labelled console shell."""

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
WEB = ROOT / "app/web"
SRC = WEB / "src"
SHELL_DIR = SRC / "components/shell"
NAV = SRC / "lib/nav.ts"
COPY = SRC / "lib/console-copy.ts"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _nav_entries() -> list[tuple[str, str, str]]:
    """(href, label key, icon) for every rail entry in the shared nav model."""
    return re.findall(r'href: "([^"]+)",\s*label: ROUTE_LABELS\["([^"]+)"\],\s*Icon: (\w+)', _read(NAV))


def test_route_labels_have_one_source_used_by_rail_palette_and_headings() -> None:
    copy = _read(COPY)
    nav = _read(NAV)
    sidebar = _read(SHELL_DIR / "Sidebar.tsx")
    palette = _read(SHELL_DIR / "CommandPalette.tsx")

    assert "export const ROUTE_LABELS" in copy
    assert "NAV_ITEMS" in sidebar
    assert "NAV_ITEMS" in palette
    assert "label: ROUTE_LABELS" in nav
    # Palette route rows derive from the shared nav, never a parallel list.
    assert 'group: "Routes",\n    label: "' not in palette
    assert '"Violations"' not in palette
    assert '"Crosswalk diagnostics"' not in palette
    assert '"Agent API"' not in palette
    # Every rail destination's H1 is the rail label.
    pages = {
        "/dashboard": "dashboard",
        "/violations": "violations",
        "/agents": "agents",
        "/audit-log": "audit-log",
        "/connectors": "connectors",
        "/crosswalk": "crosswalk",
        "/trust-center": "trust-center",
        "/controls": "controls",
        "/evidence": "evidence",
    }
    for href, folder in pages.items():
        page = _read(SRC / "app" / folder / "page.tsx")
        assert f'ROUTE_LABELS["{href}"]' in page, folder


def test_rail_has_unique_icons_graph_and_a_settings_group() -> None:
    entries = _nav_entries()
    hrefs = [href for href, _, _ in entries]
    icons = [icon for _, _, icon in entries]

    assert len(entries) >= 20
    assert len(icons) == len(set(icons)), icons
    assert all(href == key for href, key, _ in entries)
    assert "/graph" in hrefs
    assert "/auth" in hrefs
    assert "/deploy" in hrefs
    nav = _read(NAV)
    assert '"Settings"' in nav
    for folder in ("graph", "auth", "deploy"):
        assert (SRC / "app" / folder / "page.tsx").exists()


def test_rail_is_tokenized_focusable_and_marks_the_current_page() -> None:
    sidebar = _read(SHELL_DIR / "Sidebar.tsx")
    footer = _read(SHELL_DIR / "SidebarFooter.tsx")
    topbar = _read(SHELL_DIR / "TopBar.tsx")
    tailwind = _read(WEB / "tailwind.config.ts")
    css = _read(SRC / "app/globals.css")

    assert "--topbar-h:" in css
    assert "top-[var(--topbar-h)]" in sidebar
    assert "h-[calc(100dvh-var(--topbar-h))]" in sidebar
    assert "h-[var(--topbar-h)]" in topbar
    assert "top-[52px]" not in sidebar
    assert 'aria-current={active ? "page" : undefined}' in sidebar
    assert "focus-visible:ring-2" in sidebar
    assert sidebar.count("FOCUS_RING") >= 5
    assert "focus-visible:ring-2" in footer
    assert "ChevronDown" in sidebar
    assert "rotate-180" not in sidebar
    for source in (sidebar, footer):
        assert not re.search(r"#[0-9a-fA-F]{3,6}\b", source)
    assert "text-slate-400" in footer
    assert "rail: {" in tailwind


def test_mobile_nav_uses_an_accessible_drawer_instead_of_a_noop_toggle() -> None:
    sidebar = _read(SHELL_DIR / "Sidebar.tsx")
    topbar = _read(SHELL_DIR / "TopBar.tsx")
    shell = _read(SHELL_DIR / "Shell.tsx")

    assert "hidden md:grid" in sidebar
    assert "Sidebar is compact on small screens" not in sidebar
    assert "export function MobileNav" in sidebar
    assert "@radix-ui/react-dialog" in sidebar
    assert 'aria-label="Primary"' in sidebar
    assert 'aria-label="Open navigation"' in topbar
    assert "md:hidden" in topbar
    assert "md:grid-cols-[auto_minmax(0,1fr)]" in shell


def test_breadcrumbs_are_removed_because_every_route_is_one_segment() -> None:
    assert not (SHELL_DIR / "Breadcrumbs.tsx").exists()
    assert "Breadcrumbs" not in _read(SHELL_DIR / "Shell.tsx")


def test_shell_respects_reduced_motion_without_exit_remounts() -> None:
    shell = _read(SHELL_DIR / "Shell.tsx")

    assert 'MotionConfig reducedMotion="user"' in shell
    assert "AnimatePresence" not in shell
    assert "key={normalizedPathname}" in shell


def test_command_palette_is_an_accessible_combobox() -> None:
    palette = _read(SHELL_DIR / "CommandPalette.tsx")
    topbar = _read(SHELL_DIR / "TopBar.tsx")

    assert 'role="combobox"' in palette
    assert "aria-controls=" in palette
    assert "aria-activedescendant=" in palette
    assert 'role="listbox"' in palette
    assert 'role="option"' in palette
    assert "aria-selected={active}" in palette
    assert "scrollIntoView" in palette
    assert "bg-ink text-surface" not in palette
    assert "bg-brand/15" in palette
    assert "assets" not in topbar


def test_topbar_status_and_notifications_are_reachable_at_every_size() -> None:
    topbar = _read(SHELL_DIR / "TopBar.tsx")
    user_menu = _read(SHELL_DIR / "UserMenu.tsx")

    assert 'role="status"' in topbar
    assert "aria-label={statusLabel}" in topbar
    assert "xl:inline-flex" not in topbar
    assert 'href="/audit-log"' in user_menu
    assert "sm:hidden" in user_menu


def test_buttons_and_kpi_chips_keep_white_text_on_dark_enough_fills() -> None:
    button = _read(SRC / "components/ui/button.tsx")
    kpi = _read(SRC / "components/ui/KpiTile.tsx")

    assert "#21c6c7" not in button
    assert "to-[#0e7490]" in button
    dark_variant = re.search(r"dark:\s*\"([^\"]+)\"", button)
    assert dark_variant and "dark:" in dark_variant.group(1)
    assert "#f79009" not in kpi
    assert "#16b364" not in kpi


def test_font_stack_only_names_fonts_the_console_ships() -> None:
    tailwind = _read(WEB / "tailwind.config.ts")

    assert '"Inter"' not in tailwind


def test_node_engine_is_declared_for_the_documented_quickstart() -> None:
    package = _read(WEB / "package.json")

    assert '"engines"' in package
    assert '"node": ">=22"' in package
    assert _read(ROOT / ".nvmrc").strip() == "22"
