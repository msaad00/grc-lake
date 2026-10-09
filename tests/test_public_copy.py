"""Public copy (README, docs, package metadata) stays factual and free of internal planning language."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PUBLIC_DOCS = sorted(
    [ROOT / "README.md", ROOT / "ROADMAP.md", *(ROOT / "docs").rglob("*.md")],
)

INTERNAL_DOCS = (
    "docs/GRC_LAKE_85_PLAN.md",
    "docs/PILOT_ROADMAP.md",
    "docs/FRAMEWORK_EXPANSION_PLAN.md",
    "docs/REPO_AUDIT.md",
    "docs/PRODUCT_SHAPE.md",
    "docs/issues/WAVE2_TRACKER.md",
    "docs/issues/WAVE3_TRACKER.md",
    ".github/internal",
)

INTERNAL_LANGUAGE = re.compile(
    r"\bmoat\b|feature parity|parity (?:map|scorecard|lens)|\b(?:identity/admin|probe|catalog) parity|"
    r"polish %|\d+% polish|\b85%|\bwave \d|\bnext wave\b|wave[23]_tracker|feels turnkey|best-in-class|"
    r"premium UX|managed GRC",
    re.IGNORECASE,
)


def test_package_description_is_factual() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["description"] == (
        "Open-source, self-hosted trust operations: read-only evidence collection, deterministic control "
        "tests, and reproducible assessment exports via API, CLI, and MCP."
    )


def test_internal_planning_docs_are_not_published() -> None:
    for relative in INTERNAL_DOCS:
        assert not (ROOT / relative).exists(), relative


def test_public_docs_do_not_link_to_removed_internal_docs() -> None:
    names = [Path(relative).name if relative.endswith(".md") else relative for relative in INTERNAL_DOCS]
    for path in PUBLIC_DOCS:
        text = path.read_text(encoding="utf-8")
        for name in names:
            assert name not in text, f"{path.relative_to(ROOT)} still references {name}"


def test_public_docs_avoid_internal_positioning_language() -> None:
    hits = []
    for path in PUBLIC_DOCS:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if INTERNAL_LANGUAGE.search(line):
                hits.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    assert not hits, "\n".join(hits)


def test_docs_index_links_every_public_doc() -> None:
    index = ROOT / "docs" / "README.md"
    text = index.read_text(encoding="utf-8")
    linked = {(index.parent / target).resolve() for target in re.findall(r"\]\(([^)#]+\.md)(?:#[^)]*)?\)", text)}
    for path in (ROOT / "docs").rglob("*.md"):
        if path == index:
            continue
        assert path.resolve() in linked, f"docs/README.md does not link {path.relative_to(ROOT)}"
    for target in linked:
        assert target.is_file(), f"docs/README.md links a missing file: {target}"


def test_roadmap_mapping_counts_match_the_effective_review_ledger() -> None:
    from security_lakehouse.safeguards import (
        contributes_to_coverage,
        coverage_by_framework,
        effective_review_state,
        load_safeguards,
    )

    states = [
        effective_review_state(member)
        for entry in load_safeguards()["safeguards"]
        for member in entry["satisfies"]
        if contributes_to_coverage(member)
    ]
    coverage = coverage_by_framework()
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    assert "Status as of v" in roadmap
    assert (
        f"{states.count('proposed'):,} of {len(states):,} safeguard-to-requirement mapping rows are proposed, "
        f"so {coverage['proposed']:,} of the {coverage['covered']:,} mapped requirements have no reviewed mapping"
    ) in roadmap
