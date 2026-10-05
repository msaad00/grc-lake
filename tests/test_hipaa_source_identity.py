"""HIPAA identifiers pinned to the current eCFR, independently of pack counts."""

import pytest

from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.catalog_versions import controls_as_of
from security_lakehouse.limited_packs import hipaa_limited_pack_specs

# 45 CFR 164.310(b)-(d), 164.312(d), and 164.316(a)-(b), checked 2026-10-05.
REFERENCES = {
    "164.310(b)": "Workstation use",
    "164.310(c)": "Workstation security",
    "164.310(d)": "Device and media controls",
    "164.312(d)": "Person or entity authentication",
    "164.316(a)": "Policies and procedures",
    "164.316(b)": "Documentation",
}


@pytest.mark.parametrize("reference,title", REFERENCES.items())
def test_missing_hipaa_standards_have_distinct_source_bound_identities(reference, title):
    specs = {spec.article_id: spec for spec in hipaa_limited_pack_specs()}
    assert reference in specs
    spec = specs[reference]
    assert spec.title == title
    assert spec.source_url.endswith(f"/section-{reference.split('(')[0]}")
    assert spec.reconciled_at == "2026-10-05"
    assert spec.required_evidence_types


def test_new_source_entries_do_not_rewrite_historical_catalogs():
    active = load_control_catalog()
    before = controls_as_of("2026-10-04")
    for reference in REFERENCES:
        identifier = f"HIPAA-{reference}"
        assert identifier in active
        assert active[identifier]["review_status"] == "proposed"
        assert identifier not in before
    # Keep supported granular references rather than silently renumbering evidence.
    assert "HIPAA-164.308(a)(1)(ii)(A)" in before
    assert "HIPAA-164.312(a)(2)(iv)" in active
