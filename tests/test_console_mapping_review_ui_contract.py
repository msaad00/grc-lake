"""Contract for the console Mapping review page: IA placement, tokens, a11y hooks."""

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
SRC = ROOT / "app/web/src"
PAGE = SRC / "app/mapping-review/page.tsx"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_mapping_review_lives_under_evaluate_with_one_label_source() -> None:
    nav = _read(SRC / "lib/nav.ts")
    copy = _read(SRC / "lib/console-copy.ts")
    assert '"/mapping-review": "Mapping review"' in copy
    entry = re.search(
        r'href: "/mapping-review",\s*label: ROUTE_LABELS\["/mapping-review"\],\s*Icon: (\w+),\s*group: "(\w+)"', nav
    )
    assert entry is not None
    assert entry.group(2) == "Evaluate"
    # Sits right after Frameworks, where the coverage it changes is shown.
    assert nav.index('href: "/frameworks"') < nav.index('href: "/mapping-review"') < nav.index('href: "/violations"')


def test_page_uses_shared_header_tokens_and_drawer() -> None:
    page = _read(PAGE)
    assert 'ROUTE_LABELS["/mapping-review"]' in page
    assert "<PageHeader" in page
    assert "<Drawer" in page
    assert "<Badge" in page
    palette = re.compile(
        r"\b(?:bg|text|border|ring)-(?:slate|gray|zinc|blue|indigo|violet|purple|sky|cyan|emerald|green|amber|orange|rose|red|yellow|teal)-\d{2,3}\b"
    )
    assert not palette.search(page)
    assert not re.search(r"#[0-9a-fA-F]{3,6}\b", page)
    assert not re.search(r"(?<![\w-])dark:[a-z]", page)


def test_page_is_labelled_for_keyboard_and_screen_readers() -> None:
    page = _read(PAGE)
    for label in (
        'aria-label="Mappings to review"',
        'aria-label="Filter by framework"',
        'aria-label="Filter by family"',
        'aria-label="Filter by review status"',
        'aria-label="Search mappings"',
        'aria-label="Review progress"',
        'aria-label="Record a decision"',
        'aria-live="polite"',
    ):
        assert label in page, label
    # The horizontally scrollable table region must be keyboard reachable.
    assert "tabIndex={0}" in page
    # The decision form never sends a reviewer: the server takes the signed-in user.
    assert "reviewer:" not in page


def test_frameworks_and_crosswalk_link_to_the_review_queue() -> None:
    assert 'href="/mapping-review"' in _read(SRC / "app/frameworks/page.tsx")
    assert 'href="/mapping-review"' in _read(SRC / "app/crosswalk/page.tsx")
