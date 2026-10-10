"""NIST SP 800-53 Rev 5 full catalog and NIST RMF (SP 800-37 Rev 2) task packs.

Identifiers, titles, and baseline membership come from the pinned official
OSCAL catalog/profiles (tools/sync_nist_800_53.py); RMF tasks from the
SP 800-37 Rev 2 task headings.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from security_lakehouse.catalog import load_control_catalog, load_framework_registry
from security_lakehouse.mappings import load_control_article_mappings
from security_lakehouse.safeguards import load_safeguards

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "frameworks/packs/data/nist_800_53_rev5_catalog.json").read_text())
RMF = json.loads((ROOT / "frameworks/packs/data/nist_rmf_800_37r2.json").read_text())


def _framework(framework_id: str) -> dict[str, dict]:
    return {cid: row for cid, row in load_control_catalog().items() if row["framework_id"] == framework_id}


def test_manifest_is_the_full_active_rev5_catalog() -> None:
    rows = MANIFEST["rows"]
    ids = [row["id"] for row in rows]
    assert MANIFEST["source"]["version"] == "5.2.0"
    assert len(ids) == len(set(ids)) == 1014
    assert len({row["family"] for row in rows}) == 20
    assert {row["family"] for row in rows} >= {"PM", "PT"}
    assert all(row["parent"] in set(ids) for row in rows if row["parent"])
    counts = {b: sum(b in row["baselines"] for row in rows) for b in ("low", "moderate", "high", "privacy")}
    assert counts == MANIFEST["source"]["baseline_counts"] == {"low": 149, "moderate": 287, "high": 370, "privacy": 96}


def test_catalog_matches_manifest_ids_titles_and_baselines() -> None:
    active = _framework("nist-800-53-rev5")
    by_ref = {row["framework_ref"].removeprefix("NIST SP 800-53 Rev 5 "): row for row in active.values()}
    assert set(by_ref) == {row["id"] for row in MANIFEST["rows"]}
    for row in MANIFEST["rows"]:
        control = by_ref[row["id"]]
        assert control["control_id"] == f"NIST-800-53-{row['id']}"
        assert control["title"] == f"{row['id']} — {row['title']}"
        assert control["nist_baselines"] == row["baselines"]


def test_moderate_baseline_is_exactly_the_fedramp_moderate_pack() -> None:
    moderate = {row["id"] for row in MANIFEST["rows"] if "moderate" in row["baselines"]}
    fedramp = {
        row["framework_ref"].removeprefix("NIST 800-53B Moderate ") for row in _framework("fedramp-moderate").values()
    }
    assert moderate == fedramp


def test_rmf_pack_has_every_task_by_step() -> None:
    tasks = _framework("nist-rmf-800-37r2")
    assert len(tasks) == 47
    steps = Counter(row["control_id"].removeprefix("NIST-RMF-")[0] for row in tasks.values())
    assert steps == {"P": 18, "C": 3, "S": 6, "I": 2, "A": 6, "R": 5, "M": 7}
    assert {row["control_id"].removeprefix("NIST-RMF-") for row in tasks.values()} == {r["id"] for r in RMF["rows"]}


def test_new_packs_are_honest_about_review_state() -> None:
    registry = load_framework_registry()
    mappings = load_control_article_mappings()
    for framework_id in ("nist-800-53-rev5", "nist-rmf-800-37r2"):
        assert registry[framework_id]["implementation_status"] == "implemented_limited_mapping"
        for control_id, control in _framework(framework_id).items():
            assert control["review_status"] == "proposed"
            assert control["source_reconciled_by"] == "automated-source-reconciliation"
            assert control_id in mappings
    assert registry["nist-800-53-rev5"]["source_sha256"] == MANIFEST["source"]["catalog_sha256"]
    assert registry["nist-rmf-800-37r2"]["source_sha256"] == RMF["source"]["pdf_sha256"]


def test_800_53_twins_share_the_review_state_of_the_identical_fedramp_mapping() -> None:
    """A FedRAMP Moderate control *is* the NIST SP 800-53 control of the same id.

    A human review of the FedRAMP mapping therefore reviews the identical
    800-53 requirement. The twin inherits that review, records where it came
    from, and must follow the original if it is ever demoted.
    """
    inherited = 0
    for safeguard in load_safeguards()["safeguards"]:
        satisfies = {m["control_id"]: m for m in safeguard["satisfies"]}
        for control_id in [c for c in satisfies if c.startswith("FEDRAMP-")]:
            original = satisfies[control_id]
            twin = satisfies.get("NIST-800-53-" + control_id.removeprefix("FEDRAMP-"))
            assert twin is not None, f"{safeguard['safeguard_id']} maps {control_id} but not its 800-53 twin"
            assert twin["framework_id"] == "nist-800-53-rev5"
            assert twin["review_status"] == original["review_status"], control_id
            if twin["review_status"] == "reviewed":
                assert twin["review_basis"] == {
                    "inherited_from": control_id,
                    "reason": "identical NIST SP 800-53 Rev 5 control",
                }
                inherited += 1
            else:
                assert "review_basis" not in twin
    assert inherited == 96
