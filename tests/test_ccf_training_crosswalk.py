"""Source-backed CCF contract for awareness and role-based training."""

from security_lakehouse.safeguards import (
    coverage_by_framework,
    load_safeguards,
    mapping_review_queue,
    safeguards_by_requirement,
)

SOURCE = {
    "name": "NIST SP 800-171 Rev. 2",
    "url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r2.pdf",
    "sha256": "298bdbfcf6a4890a564b225c893230a0b32b2e69e3b98dd898aaeb1d544c5e12",
}


def test_training_safeguard_uses_the_nist_800_171_crosswalk() -> None:
    safeguards = {entry["safeguard_id"]: entry for entry in load_safeguards()["safeguards"]}
    safeguard = safeguards["SG-TRAINING-001"]
    members = {member["control_id"]: member for member in safeguard["satisfies"]}

    assert members["CMMC-3.2.3"]["mapping_source"] == {
        **SOURCE,
        "locator": "Appendix D, Table D-2, requirement 3.2.3 maps to AT-2(2)",
    }
    assert members["CMMC-3.2.1"] == {
        "control_id": "CMMC-3.2.1",
        "framework_id": "cmmc-2-level2",
        "role": "equivalent",
        "review_status": "proposed",
        "control_version": "1.0.0",
        "current_control_version": "1.0.0",
        "mapping_source": {
            **SOURCE,
            "locator": "Appendix D, Table D-2, requirement 3.2.1 maps to AT-2",
        },
    }
    assert members["CMMC-3.2.2"] == {
        "control_id": "CMMC-3.2.2",
        "framework_id": "cmmc-2-level2",
        "role": "equivalent",
        "review_status": "proposed",
        "control_version": "1.0.0",
        "current_control_version": "1.0.0",
        "mapping_source": {
            **SOURCE,
            "locator": "Appendix D, Table D-2, requirement 3.2.2 maps to AT-3",
        },
    }
    assert members["FEDRAMP-AT-2"]["mapping_source"] == {
        **SOURCE,
        "locator": "Appendix D, Table D-2, requirement 3.2.1 maps to AT-2",
    }
    assert members["FEDRAMP-AT-3"]["mapping_source"] == {
        **SOURCE,
        "locator": "Appendix D, Table D-2, requirement 3.2.2 maps to AT-3",
    }

    mappings = safeguards_by_requirement()
    assert mappings["CMMC-3.2.1"] == ["SG-TRAINING-001"]
    assert mappings["CMMC-3.2.2"] == ["SG-TRAINING-001"]


def test_training_crosswalk_closes_two_cmmc_evaluation_gaps_without_overstating_attestation() -> None:
    payload = load_safeguards()
    training = next(entry for entry in payload["safeguards"] if entry["safeguard_id"] == "SG-TRAINING-001")
    training["satisfies"] = [
        member for member in training["satisfies"] if member["control_id"] not in {"CMMC-3.2.1", "CMMC-3.2.2"}
    ]

    without_training_crosswalk = coverage_by_framework(payload)
    coverage = coverage_by_framework()

    assert coverage["safeguards"] == without_training_crosswalk["safeguards"]
    assert coverage["covered"] == without_training_crosswalk["covered"] + 2
    assert coverage["uncovered"] == without_training_crosswalk["uncovered"] - 2
    assert coverage["reviewed"] == without_training_crosswalk["reviewed"]
    assert coverage["proposed"] == without_training_crosswalk["proposed"] + 2
    assert coverage["frameworks"]["cmmc-2-level2"]["controls"] == 110
    assert (
        coverage["frameworks"]["cmmc-2-level2"]["covered"]
        == without_training_crosswalk["frameworks"]["cmmc-2-level2"]["covered"] + 2
    )


def test_training_crosswalk_source_is_visible_in_the_review_queue() -> None:
    queue = {
        item["control_id"]: item
        for item in mapping_review_queue(framework_id="cmmc-2-level2")
        if item["control_id"] in {"CMMC-3.2.1", "CMMC-3.2.2"}
    }

    assert queue["CMMC-3.2.1"]["mapping_source"]["locator"].endswith("3.2.1 maps to AT-2")
    assert queue["CMMC-3.2.2"]["mapping_source"]["locator"].endswith("3.2.2 maps to AT-3")

    fedramp_queue = {
        item["control_id"]: item
        for item in mapping_review_queue(framework_id="fedramp-moderate")
        if item["control_id"] in {"FEDRAMP-AT-2", "FEDRAMP-AT-3"}
    }
    assert fedramp_queue["FEDRAMP-AT-2"]["mapping_source"]["locator"].endswith("3.2.1 maps to AT-2")
    assert fedramp_queue["FEDRAMP-AT-3"]["mapping_source"]["locator"].endswith("3.2.2 maps to AT-3")
