"""Reconcile baseline labels and the compatibility control map from the catalog.

The legacy fedramp-moderate identifier is retained for compatibility. Its
287-entry source is the NIST SP 800-53B Moderate baseline; this does not import
the FedRAMP overlay, parameters, assessment requirements, or authorization.
"""

from pathlib import Path

from security_lakehouse.catalog_versions import write_bundle_lock
from security_lakehouse.framework_packs import _read_json, _write_json


def main():
    root = Path(__file__).resolve().parents[1]
    path = root / "controls/catalog.json"
    catalog = _read_json(path)
    for row in catalog["controls"]:
        if row.get("framework_id") == "fedramp-moderate":
            for key in ("framework", "framework_ref", "evidence_requirement", "mapping_rationale", "title"):
                if isinstance(row.get(key), str):
                    row[key] = row[key].replace("FedRAMP Moderate", "NIST 800-53B Moderate")
    _write_json(path, catalog)
    registry = _read_json(root / "frameworks/registry.json")
    for row in registry["frameworks"]:
        if row["framework_id"] == "fedramp-moderate":
            row["name"] = "NIST SP 800-53B Moderate baseline (FedRAMP foundation only)"
    _write_json(root / "frameworks/registry.json", registry)
    _write_json(
        root / "mappings/control_map.json",
        {
            "controls": [
                {key: row[key] for key in ("control_id", "framework", "title", "risk_domain", "owner")}
                for row in catalog["controls"]
            ]
        },
    )
    controls = {r["control_id"]: r for r in catalog["controls"]}
    history = [
        __import__("json").loads(line)
        for line in (root / "controls/history.jsonl").read_text().splitlines()
        if line.strip()
    ]
    safeguards = _read_json(root / "controls/safeguards.json")
    for entry in safeguards["safeguards"]:
        reviewed = str(entry.get("reviewed_at") or "")[:10]
        for member in entry["satisfies"]:
            if "control_version" in member:
                continue
            cid = member["control_id"]
            candidates = [
                r
                for r in history
                if r["control_id"] == cid
                and str(r.get("valid_from") or "")[:10] <= reviewed < str(r.get("valid_to") or "9999")[:10]
            ]
            version = candidates[-1] if candidates else controls[cid]
            member["control_version"] = version.get("version", "1.0.0")
    _write_json(root / "controls/safeguards.json", safeguards)
    write_bundle_lock()


if __name__ == "__main__":
    main()
