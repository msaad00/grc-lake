"""The mapping-review states have one vocabulary: server labels, the console
glossary, and CLI help all say the same thing."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from security_lakehouse.cli import main
from security_lakehouse.safeguards import REVIEW_STATE_DEFINITIONS, REVIEW_STATE_LABELS

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "app/web/src"


def _console_glossary() -> dict[str, tuple[str, str]]:
    source = (WEB / "lib/console-copy.ts").read_text(encoding="utf-8")
    block = source[source.index("export const MAPPING_REVIEW_GLOSSARY") :]
    block = block[: block.index("} as const;")]
    entries = re.findall(
        r"(\w+): \{\s*label: \"([^\"]+)\",\s*definition:\s*\"([^\"]+)\",\s*\}",
        block,
    )
    return {key: (label, definition) for key, label, definition in entries}


def test_console_glossary_matches_server_labels_and_definitions() -> None:
    glossary = _console_glossary()
    assert set(glossary) == set(REVIEW_STATE_LABELS)
    for state, (label, definition) in glossary.items():
        assert label.lower() == REVIEW_STATE_LABELS[state]
        assert definition == REVIEW_STATE_DEFINITIONS[state]


def test_cli_review_help_explains_every_state(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["frameworks", "review", "--help"])
    help_text = " ".join(capsys.readouterr().out.split())
    for state, label in REVIEW_STATE_LABELS.items():
        assert f"{label}: {REVIEW_STATE_DEFINITIONS[state]}" in help_text, state


def test_console_surfaces_use_the_glossary() -> None:
    for rel in ("app/mapping-review/page.tsx", "app/crosswalk/page.tsx", "app/frameworks/page.tsx"):
        source = (WEB / rel).read_text(encoding="utf-8")
        assert "MAPPING_REVIEW_GLOSSARY" in source, rel
        assert "org-reviewed ·" not in source, rel
    review = (WEB / "app/mapping-review/page.tsx").read_text(encoding="utf-8")
    assert "{item.review_label}" not in review
