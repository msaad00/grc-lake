"""Frozen reports preserve data and remain usable without a running API."""

import json
import re
from html.parser import HTMLParser

import pytest

from security_lakehouse import dashboard


def _data():
    return {
        "synthetic_fixture": True,
        "framework_catalog_counts": {"SOC 2": 10},
        "posture": {
            "schema_version": "trustops.assessment.v1",
            "evaluated_at": "2026-10-06T12:00:00Z",
            "assessment_hash": "recorded-hash",
            "posture": {"score": 80, "open_violation_count": 1, "control_count": 5},
            "frameworks": [{"framework": "SOC 2", "control_count": 5, "score": 80, "state": "attention_required"}],
            "violations": [
                {
                    "control_id": "SOC2-CC6.1",
                    "severity": "high",
                    "asset_id": '<asset>&</script><img src=x onerror="alert(1)">',
                    "asset_owner": "Audit owner",
                }
            ],
        },
        "controls": [],
        "events": [],
    }


class _Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def test_export_embeds_exact_json_and_no_active_evidence_markup(tmp_path, monkeypatch):
    data = _data()
    monkeypatch.setattr(dashboard, "_load_app_data", lambda lake: data)
    body = dashboard.render_dashboard(tmp_path, tmp_path / "report.html").read_text()
    script = re.search(r'<script id="app-data"[^>]*>(.*?)</script>', body, re.S)
    assert script
    assert json.loads(script[1]) == data
    parsed = _Tags()
    parsed.feed(body)
    assert not any(tag == "img" and attrs.get("src") == "x" for tag, attrs in parsed.tags)


def test_report_renders_frozen_values_without_executable_scripts(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "_load_app_data", lambda lake: _data())
    body = dashboard.render_dashboard(tmp_path, tmp_path / "report.html").read_text()
    parsed = _Tags()
    parsed.feed(body)
    assert all(attrs.get("type") == "application/json" for tag, attrs in parsed.tags if tag == "script")
    assert "Framework coverage" in body
    assert "5 / 10" in body
    assert "Audit owner" in body
    assert "recorded-hash" in body


def test_sparse_frozen_report_does_not_present_numeric_readiness(tmp_path, monkeypatch):
    data = _data()
    data["posture"]["frameworks"][0]["control_count"] = 4
    monkeypatch.setattr(dashboard, "_load_app_data", lambda lake: data)
    body = dashboard.render_dashboard(tmp_path, tmp_path / "report.html").read_text()
    visible = body.split("</script>", 1)[1]
    assert "Insufficient coverage" in visible
    assert "4 / 10" in visible
    assert ">80%<" not in visible


@pytest.mark.parametrize("total", [None, 0])
def test_missing_catalog_denominator_suppresses_report_score(tmp_path, monkeypatch, total):
    data = _data()
    data["framework_catalog_counts"]["SOC 2"] = total
    monkeypatch.setattr(dashboard, "_load_app_data", lambda lake: data)
    body = dashboard.render_dashboard(tmp_path, tmp_path / "report.html").read_text()
    visible = body.split("</script>", 1)[1]
    assert "Insufficient coverage" in visible
    assert ">80%<" not in visible
