"""Benchmark results must check labeled CCF outcomes, not only row counts."""

from datetime import UTC, datetime

from tools.benchmark_assessment_pipeline import worker


def test_ccf_workload_checks_outcomes_and_source_tenant_boundaries(tmp_path):
    result = worker(10, workload="ccf", root=tmp_path, base_time=datetime.now(UTC))
    assert result["silver_count"] == 10
    assert result["integrity_ok"]
    assert result["ccf_labels_ok"]
    assert result["ccf_asset_count"] == 10
    assert result["ccf_asset_result_count"] == 8
    assert result["ccf_status_counts"] == {"pass": 2, "fail": 2, "not_evaluated": 2, "stale": 2}
