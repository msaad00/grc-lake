"""Refuse to publish a wheel that is missing the console or its catalogs.

`src/security_lakehouse/web/dist` is gitignored and built by `make web-build`.
`pyproject.toml` declares it as package data, so a wheel built *before* that step
is valid, installable, and silently consoleless — `/console/` is mounted only
when a built console is present, so the documented URL 404s for everyone who
installs it.

The control catalogs have the same shape of problem: they ship as data-files, and
a wheel without them installs fine and then cannot evaluate anything.

Both failures are invisible until a user hits them, which is why this runs
between build and publish.

    python tools/verify_wheel.py dist/*.whl
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

# Prefix -> what its absence would break for someone who pip-installs the wheel.
REQUIRED: dict[str, str] = {
    "security_lakehouse/web/dist/index.html": "the console (/console/ would 404)",
    "controls/catalog.json": "the control catalog (nothing to evaluate)",
    "frameworks/registry.json": "the framework registry",
    "connectors/catalog.json": "the connector catalog",
    "controls/safeguards.json": "the CCF safeguards (framework coverage and review queue)",
    "controls/families.json": "the CCF family taxonomy (safeguard validation and family ledger)",
}

# Manifest-driven packs are runtime inputs, including files loaded indirectly
# through PACK_DATA_DIR. Discover them from the checkout so future packs cannot
# silently pass a stale, hand-maintained wheel gate.
PACK_DATA = Path(__file__).resolve().parents[1] / "frameworks" / "packs" / "data"
REQUIRED.update(
    {
        f"frameworks/packs/data/{path.name}": "framework pack evaluation and source provenance"
        for path in PACK_DATA.glob("*.json")
    }
)

RESOURCE_ROOT = Path(__file__).resolve().parents[1] / "src/security_lakehouse/resources"
REQUIRED.update(
    {
        "security_lakehouse/resources/"
        + path.relative_to(RESOURCE_ROOT).as_posix(): "cloud linking and evidence schemas"
        for path in RESOURCE_ROOT.rglob("*")
        if path.is_file()
    }
)


def verify(wheel: Path) -> list[str]:
    """Return a list of problems; empty means the wheel is publishable."""
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())

    problems: list[str] = []
    for required, why in REQUIRED.items():
        # data-files land under a `*.data/data/` prefix, package-data does not.
        if not any(name == required or name.endswith("/" + required) for name in names):
            problems.append(f"missing {required} -- {why}")

    console_files = [n for n in names if "/web/dist/" in n]
    if 0 < len(console_files) < 5:
        problems.append(f"console looks truncated: only {len(console_files)} files under web/dist")

    return problems


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: verify_wheel.py <wheel> [<wheel> ...]", file=sys.stderr)
        return 2

    failed = False
    for arg in argv:
        wheel = Path(arg)
        if not wheel.is_file():
            print(f"not a file: {wheel}", file=sys.stderr)
            failed = True
            continue
        problems = verify(wheel)
        if problems:
            failed = True
            print(f"{wheel.name}: NOT publishable", file=sys.stderr)
            for problem in problems:
                print(f"  - {problem}", file=sys.stderr)
        else:
            with zipfile.ZipFile(wheel) as archive:
                console = sum(1 for n in archive.namelist() if "/web/dist/" in n)
            print(f"{wheel.name}: ok ({console} console files, catalogs present)")

    if failed:
        print("\nBuild the console before packaging: make web-install web-build", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
