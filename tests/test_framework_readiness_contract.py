"""Framework readiness metadata must preserve honest planned boundaries."""

from security_lakehouse.framework_provenance import build_framework_view


def test_soc1_planned_view_explains_boundary_and_next_step() -> None:
    soc1 = next(row for row in build_framework_view() if row["framework_id"] == "soc1")

    assert soc1["implementation_status"] == "planned"
    assert soc1["coverage_boundary"]
    assert "service-specific" in soc1["coverage_boundary"]
    assert soc1["evidence_focus"]
    assert soc1["next_step"]


def test_planned_framework_readiness_metadata_does_not_create_controls() -> None:
    soc1 = next(row for row in build_framework_view() if row["framework_id"] == "soc1")

    assert soc1["control_count"] == 0
    assert soc1["implemented_control_count"] == 0
    assert soc1["mapping_coverage_pct"] == 0.0


def test_iso_27701_2019_view_says_withdrawn_and_points_to_2025() -> None:
    iso_27701 = next(row for row in build_framework_view() if row["framework_id"] == "iso-27701-2019")

    assert iso_27701["implementation_status"] == "planned"
    assert "withdrawn" in iso_27701["coverage_boundary"]
    assert "iso-27701-2025" in iso_27701["next_step"]
    assert iso_27701["evidence_focus"]
    assert iso_27701["control_count"] == 0


def test_iso_27701_2025_view_states_limited_boundary() -> None:
    iso_27701 = next(row for row in build_framework_view() if row["framework_id"] == "iso-27701-2025")

    assert iso_27701["implementation_status"] == "implemented_limited_mapping"
    assert "10 of the 78" in iso_27701["coverage_boundary"]
    assert iso_27701["control_count"] == 10
