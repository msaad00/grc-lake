#!/usr/bin/env python3
"""Fail CI when tracked copy uses forbidden or retired product names.

Policy: public copy never names other vendors' GRC products.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]

# Case-insensitive whole-word-ish matches for GRC competitors and interview leaks.
FORBIDDEN = re.compile(
    r"\b("
    r"drata|vanta|secureframe|sprinto|thoropass|onetrust|auditboard|"
    r"logicgate|hyperproof|scrut\s+automation|comp\.?ai|"
    r"harvey\s+trust|grc-access-review|grc-review-harvey"
    r")\b",
    re.IGNORECASE,
)

# GRC Lake is the only customer-facing product name. Keep the retired alias
# from drifting back into UI, documentation, actions, or metadata.
RETIRED_BRAND = re.compile(r"\bko" r"da\b", re.IGNORECASE)

# The current GitHub/GHCR owner is a technical identifier, not a product name.
# Match the whole owner so look-alike namespaces do not gain an exemption.
REPOSITORY_OWNER = re.compile(r"(?<![\w-])ko" r"da-ai-studio(?![\w-])", re.IGNORECASE)

RETIRED_VISUAL_BRAND = re.compile(r"\b(?:trust\s*ops|ko" r"da)\b", re.IGNORECASE)

SCAN_ROOTS = (
    ROOT / "README.md",
    ROOT / "CHANGELOG.md",
    ROOT / "ROADMAP.md",
    ROOT / "docs",
    ROOT / "app",
    ROOT / "src",
    ROOT / "tests",
    ROOT / "deploy",
    ROOT / "tools",
    ROOT / ".github",
)

SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".lock"}
SKIP_PARTS = {
    "node_modules",
    ".next",
    "build",
    "dist",
    ".venv",
    "__pycache__",
    "grc-review-standalone",
}


def _iter_files() -> list[Path]:
    files: list[Path] = []
    for root in SCAN_ROOTS:
        if root.is_file():
            files.append(root)
            continue
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.name == "check_brand_compliance.py":
                continue
            if any(part in SKIP_PARTS for part in path.parts):
                continue
            if path.suffix.lower() in SKIP_SUFFIXES:
                continue
            files.append(path)
    return sorted(set(files))


def main() -> int:
    violations: list[str] = []
    for path in _iter_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if path.suffix.lower() == ".svg":
            # Join text within each element: a wordmark can span styled tspans.
            try:
                root = ElementTree.fromstring(text)
            except ElementTree.ParseError as exc:
                violations.append(f"{path.relative_to(ROOT)}: invalid SVG: {exc}")
                continue
            for node in root.iter():
                if node.tag.rsplit("}", 1)[-1] in {"text", "title", "desc"}:
                    copy = "".join(node.itertext())
                    for match in RETIRED_VISUAL_BRAND.finditer(copy):
                        violations.append(f"{path.relative_to(ROOT)}: retired visual brand {match.group(0)!r}")
        for match in FORBIDDEN.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            violations.append(f"{path.relative_to(ROOT)}:{line}: {match.group(0)!r}")
        owner_starts = {match.start() for match in REPOSITORY_OWNER.finditer(text)}
        for match in RETIRED_BRAND.finditer(text):
            if match.start() in owner_starts:
                continue
            line = text.count("\n", 0, match.start()) + 1
            violations.append(f"{path.relative_to(ROOT)}:{line}: retired brand {match.group(0)!r}")

    if violations:
        print("Brand compliance check failed — forbidden names in tracked copy:")
        for line in violations:
            print(f"  - {line}")
        print('Use generic terms like "managed GRC SaaS" (see docs/BRAND.md).')
        return 1

    print(f"brand compliance check passed ({len(_iter_files())} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
