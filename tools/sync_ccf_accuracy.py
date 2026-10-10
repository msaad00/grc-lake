"""Reconcile second-pass CCF metadata, preserving review state and evidence rules.

ISO short labels are in the source manifest; runtime readers accept the legacy
proposed-row reviewed_* keys. Run with PYTHONPATH=src python tools/sync_ccf_accuracy.py.
"""

from pathlib import Path

from security_lakehouse.catalog import source_provenance
from security_lakehouse.catalog_versions import write_bundle_lock
from security_lakehouse.framework_packs import _read_json, _write_json, iso_27001_2022_specs


def sync(root: Path) -> None:
    titles = {s.control_id: s.title for s in iso_27001_2022_specs()}
    for filename, key in (("controls/catalog.json", "controls"), ("mappings/control_map.json", "controls")):
        path = root / filename
        payload = _read_json(path)
        for i, row in enumerate(payload[key]):
            row = source_provenance(row)
            if row["control_id"] in titles:
                row["title"] = titles[row["control_id"]]
            payload[key][i] = row
        _write_json(path, payload)
    path = root / "mappings/control_articles.json"
    payload = _read_json(path)
    for row in payload["mappings"]:
        row["articles"] = [source_provenance(a) for a in row["articles"]]
        if row["control_id"] in titles:
            for article in row["articles"]:
                article["title"] = titles[row["control_id"]]
    _write_json(path, payload)
    path = root / "controls/safeguards.json"
    payload = _read_json(path)
    safeguards = {s["safeguard_id"]: s for s in payload["safeguards"]}
    identity = safeguards["SG-IDENTITY-001"]["satisfies"]
    moved = [m for m in identity if m["control_id"] == "CMMC-3.9.1"]
    identity[:] = [m for m in identity if m["control_id"] != "CMMC-3.9.1"]
    safeguards["SG-PERSONNELSCREENING-001"]["satisfies"].extend(moved)
    for safeguard in safeguards.values():
        for member in safeguard["satisfies"]:
            if member["control_id"] == "PCI-DSS-8" or (
                member["control_id"] == "GDPR-Art.33" and safeguard["safeguard_id"] == "SG-INCIDENTRESPONSE-001"
            ):
                member["role"] = "supporting"
            if safeguard["safeguard_id"] == "SG-INCIDENTRESPONSE-001" and member["control_id"] == "NIST-800-53-IR-6":
                # Incident Reporting anchors this safeguard; the more specific
                # notification safeguard owns the sole Art.33 primary mapping.
                member["role"] = "primary"
    _write_json(path, payload)
    write_bundle_lock()


if __name__ == "__main__":
    sync(Path(__file__).resolve().parents[1])
