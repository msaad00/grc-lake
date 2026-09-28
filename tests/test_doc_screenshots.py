"""Console screenshots in docs/images are cropped to their content."""

from pathlib import Path

import pytest
from PIL import Image

IMAGES = Path(__file__).resolve().parents[1] / "docs" / "images"
SCALE = 2
RAIL_WIDTH = 248
# A capture ends 40px below the page content, or 32px below the last rail nav
# group when the rail is taller. On the shortest pages the rail sets the
# height, leaving up to ~200px under the content; a fixed-height capture left
# 270-340px there.
MAX_BLANK_BOTTOM = 240
SCREENSHOTS = sorted(IMAGES.glob("trustops-demo-*.png"))
DARK = [path for path in SCREENSHOTS if path.stem.endswith("-dark")]


def _width(path: Path) -> int:
    with Image.open(path) as image:
        return image.width


FULL_WIDTH_PAGES = [path for path in SCREENSHOTS if _width(path) == 1440 * SCALE]


def test_screenshots_exist() -> None:
    assert len(SCREENSHOTS) >= 20
    assert len(FULL_WIDTH_PAGES) >= 10


DRAWER_CROPS = {"trustops-demo-triage", "trustops-demo-control-drawer"}
MOBILE_PAGES = {"trustops-demo-overview-mobile"}


@pytest.mark.parametrize("path", SCREENSHOTS, ids=lambda path: path.name)
def test_crop_policy_keeps_the_app_shell(path: Path) -> None:
    """Pages are captured with the shell at desktop or phone width; only drawers crop."""
    stem = path.stem.removesuffix("-dark")
    if stem in DRAWER_CROPS:
        return
    expected = 390 if stem in MOBILE_PAGES else 1440
    assert _width(path) == expected * SCALE, f"{path.name} is cropped"


def test_mapping_review_and_mobile_captures_exist() -> None:
    names = {path.name for path in SCREENSHOTS}
    assert {
        "trustops-demo-mapping-review.png",
        "trustops-demo-mapping-review-dark.png",
        "trustops-demo-overview-mobile.png",
    } <= names


def test_control_families_and_crosswalk_captures_are_linked_from_the_readme() -> None:
    readme = (IMAGES.parents[1] / "README.md").read_text(encoding="utf-8")
    for name in ("trustops-demo-control-families.png", "trustops-demo-crosswalk.png"):
        assert (IMAGES / name).is_file(), name
        assert f"docs/images/{name}" in readme, name


@pytest.mark.parametrize("dark", DARK, ids=lambda path: path.name)
def test_light_and_dark_pairs_share_dimensions(dark: Path) -> None:
    light = dark.with_name(dark.name.replace("-dark.png", ".png"))
    with Image.open(light) as light_image, Image.open(dark) as dark_image:
        assert light_image.size == dark_image.size


def _blank_rows_at_bottom(image: Image.Image) -> int:
    """Rows at the bottom of the main column (right of the rail) that are one flat color."""
    width, height = image.size
    column = image.convert("RGB").crop(((RAIL_WIDTH + 1) * SCALE, 0, width, height))
    background = column.getpixel((0, height - 1))
    rows = 0
    for y in range(height - 1, -1, -1):
        if column.crop((0, y, column.width, y + 1)).getcolors(maxcolors=1) != [(column.width, background)]:
            break
        rows += 1
    return rows // SCALE


@pytest.mark.parametrize("path", FULL_WIDTH_PAGES, ids=lambda path: path.name)
def test_page_captures_end_near_their_content(path: Path) -> None:
    with Image.open(path) as image:
        blank = _blank_rows_at_bottom(image)
    assert blank <= MAX_BLANK_BOTTOM, f"{path.name} ends in {blank}px of empty page"
