from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.framework_packs import iso_42001_2023_specs


def test_iso_annex_responsible_development_does_not_replace_risk_treatment_clause():
    annex = next(spec for spec in iso_42001_2023_specs() if spec.framework_ref == "ISO 42001:2023 A.6.1.3")
    assert annex.control_id != "ISO42001-6.1.3"
    controls = load_control_catalog()
    assert "risk treatment" in controls["ISO42001-6.1.3"]["title"].lower()
    assert annex.control_id in controls
    assert "design" in controls[annex.control_id]["title"].lower()


def test_soc2_reference_titles_follow_corrected_topics():
    from security_lakehouse.framework_packs import soc2_full_pack_specs
    from security_lakehouse.mappings import load_control_article_mappings

    specs = {row.article_id: row for row in soc2_full_pack_specs()}
    assert "outside" in specs["CC6.6"].title.lower()
    assert "security incident" in specs["CC7.5"].title.lower()
    mappings = load_control_article_mappings()
    for ref in ("CC6.4", "CC6.5", "CC6.6", "CC7.5", "CC9.1", "P5.2"):
        assert mappings[f"SOC2-{ref}"]["articles"][0]["title"] == specs[ref].title


def test_iso_annex_controls_never_share_an_id_with_a_management_clause():
    controls = load_control_catalog()
    for spec in iso_42001_2023_specs():
        row = controls.get(spec.control_id)
        assert row is not None, spec.control_id
        assert row["framework_ref"] == spec.framework_ref, (
            f"{spec.framework_ref} resolves to {spec.control_id}, which the catalog uses for {row['framework_ref']}"
        )
