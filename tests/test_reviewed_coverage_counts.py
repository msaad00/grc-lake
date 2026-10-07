from security_lakehouse.safeguards import _add_safeguard, _ledger_counts, _mapping_ledger


def test_contextual_review_is_not_counted_as_attestable_coverage():
    ledger = _mapping_ledger()
    _add_safeguard(
        ledger,
        {
            "satisfies": [
                {"control_id": "SOC2-CC6.1", "framework_id": "soc2", "review_status": "reviewed", "role": "supporting"}
            ]
        },
    )
    result = _ledger_counts(ledger)
    assert result["contextual_mapping_count"] == 1
    assert result["reviewed_mapping_count"] == 0


def test_readme_summary_uses_current_version_reviewed_coverage():
    from tools.render_readme_header import render_readme_summary

    from security_lakehouse.safeguards import coverage_by_framework

    count = coverage_by_framework()["reviewed"]
    assert f"**{count:,} have reviewed mappings**" in render_readme_summary()
