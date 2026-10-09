"""Palette-quantize README screenshots so 2x captures stay small in the repo.

Pillow ships with the dev/server extras (via reportlab). UI screenshots are
flat-colored, so a 256-color palette without dithering is visually lossless.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image


def optimize(path: Path) -> tuple[int, int]:
    before = path.stat().st_size
    with Image.open(path) as image:
        if image.mode == "P":
            return before, before
        quantized = image.convert("RGB").quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
    quantized.save(path, optimize=True)
    return before, path.stat().st_size


def main(argv: list[str]) -> int:
    paths = [Path(arg) for arg in argv] or sorted(Path("docs/images").glob("grc-lake-demo-*.png"))
    total_before = total_after = 0
    for path in paths:
        before, after = optimize(path)
        total_before += before
        total_after += after
    print(f"optimized {len(paths)} screenshots: {total_before // 1024} KB -> {total_after // 1024} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
