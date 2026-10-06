"""Short internal titles follow the topic of the cited AICPA criterion."""

import pytest

from security_lakehouse.catalog import load_control_catalog
from security_lakehouse.framework_packs import soc2_full_pack_specs


@pytest.mark.parametrize(
    ("criterion", "topic"),
    [
        ("CC6.4", "physical access"),
        ("CC6.5", "retirement"),
        ("CC9.1", "business disruption"),
        ("P5.2", "correction"),
        ("P6.2", "authorized disclosure records"),
        ("P6.3", "unauthorized disclosure records"),
        ("P6.4", "third-party privacy compliance"),
        ("P6.5", "third-party breach reporting"),
        ("P6.6", "breach notification"),
        ("P6.7", "disclosure accounting"),
    ],
)
def test_soc2_criterion_topic(criterion, topic):
    specs = {s.control_id: s for s in soc2_full_pack_specs()}
    control_id = f"SOC2-{criterion}"
    assert topic in specs[control_id].title.lower()
    assert topic in load_control_catalog()[control_id]["title"].lower()
