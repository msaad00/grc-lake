"""Reconcile corrected SOC 2 internal topics without changing mapping reviews.

Source: AICPA 2017 TSC, revised points of focus 2022, CC6.4/5, CC9.1,
P5.2 and P6.2-7. These are short internal summaries, not licensed criterion text.
Run with PYTHONPATH=src python tools/sync_soc2_titles.py.
"""

from security_lakehouse.catalog_versions import write_bundle_lock
from security_lakehouse.framework_packs import DEFAULT_CONTROL_CATALOG, _read_json, _write_json, soc2_full_pack_specs

CORRECTED = {"CC6.4", "CC6.5", "CC9.1", "P5.2", *(f"P6.{i}" for i in range(2, 8))}


def main():
    specs = {s.control_id: s for s in soc2_full_pack_specs() if s.article_id in CORRECTED}
    payload = _read_json(DEFAULT_CONTROL_CATALOG)
    for row in payload["controls"]:
        if row["control_id"] in specs:
            spec = specs[row["control_id"]]
            row["title"] = spec.title
            row["evidence_requirement"] = spec.evidence_requirement
    _write_json(DEFAULT_CONTROL_CATALOG, payload)
    write_bundle_lock()


if __name__ == "__main__":
    main()
