"""Reconcile corrected SOC 2 internal topics without changing mapping reviews.

Source: AICPA 2017 TSC, revised points of focus 2022, CC6.4/5, CC9.1,
P5.2 and P6.2-7. These are short internal summaries, not licensed criterion text.
Run with PYTHONPATH=src python tools/sync_soc2_titles.py.
"""

from security_lakehouse.catalog_versions import write_bundle_lock
from security_lakehouse.framework_packs import (
    DEFAULT_CONTROL_CATALOG,
    DEFAULT_MAPPINGS,
    _read_json,
    _write_json,
    soc2_full_pack_specs,
)

CORRECTED = {"CC6.4", "CC6.5", "CC6.6", "CC7.5", "CC9.1", "P5.2", *(f"P6.{i}" for i in range(2, 8))}


def main():
    specs = {s.control_id: s for s in soc2_full_pack_specs() if s.article_id in CORRECTED}
    payload = _read_json(DEFAULT_CONTROL_CATALOG)
    for row in payload["controls"]:
        if row["control_id"] in specs:
            spec = specs[row["control_id"]]
            row["title"] = spec.title
            row["evidence_requirement"] = spec.evidence_requirement
    _write_json(DEFAULT_CONTROL_CATALOG, payload)
    mappings = _read_json(DEFAULT_MAPPINGS)
    for row in mappings["mappings"]:
        spec = specs.get(row["control_id"])
        if spec is not None:
            for article in row.get("articles", []):
                if article.get("article_id") == spec.article_id:
                    article["title"] = spec.title[:120]
    _write_json(DEFAULT_MAPPINGS, mappings)
    control_map = DEFAULT_CONTROL_CATALOG.parent.parent / "mappings/control_map.json"
    compatibility = _read_json(control_map)
    for row in compatibility["controls"]:
        if row["control_id"] in specs:
            row["title"] = specs[row["control_id"]].title
    _write_json(control_map, compatibility)
    write_bundle_lock()


if __name__ == "__main__":
    main()
