"""Refresh CCF documentation figures from the same version-aware coverage API."""

import re
from pathlib import Path

from security_lakehouse.safeguards import coverage_by_framework


def main():
    coverage = coverage_by_framework()
    path = Path(__file__).resolve().parents[1] / "docs/COMMON_CONTROL_FRAMEWORK.md"
    text = path.read_text()
    headline = (
        f"{coverage['safeguards']} safeguards map {coverage['covered']} of {coverage['controls']} requirements "
        f"({coverage['coverage_pct']}%) — {coverage['maintainer_reviewed']} maintainer-reviewed, "
        f"{coverage['org_reviewed']} org-reviewed ({coverage['reviewed_pct']}% attestable), "
        f"{coverage['proposed']} proposed; {coverage['rejected_mappings']} mapping(s) rejected by the org"
    )
    text = re.sub(r"^\d+ safeguards map .*$", lambda _: headline, text, flags=re.M)
    for name, row in coverage["frameworks"].items():
        line = f"| {name:19s} | {row['controls']:12d} | {row['covered']:6d} | {row['coverage_pct']:5.1f}% |"
        text = re.sub(r"^\| " + re.escape(name) + r"\s+\|.*$", lambda _, line=line: line, text, flags=re.M)
    text = re.sub(r"\b\d+ requirements, each carrying", f"{coverage['controls']} requirements, each carrying", text)
    text = re.sub(r"\b\d+ distinct evidence", f"{coverage['controls']} distinct evidence", text)
    text = re.sub(r"statements for \d+ controls", f"statements for {coverage['controls']} controls", text)
    text = re.sub(
        r"`asset_types` on all \d+ requirements", f"`asset_types` on all {coverage['controls']} requirements", text
    )
    text = re.sub(r"\d+ of \d+ titles still contain", "Some titles still contain", text)
    path.write_text(text)


if __name__ == "__main__":
    main()
