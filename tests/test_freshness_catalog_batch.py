"""A batch uses one connector catalog view, without repeated plugin discovery."""

from security_lakehouse import evidence_freshness, programs


def test_control_test_batch_loads_connector_catalog_once(monkeypatch):
    loads = []
    original = evidence_freshness.load_connector_catalog

    def tracked():
        loads.append(True)
        return original()

    monkeypatch.setattr(evidence_freshness, "load_connector_catalog", tracked)
    monkeypatch.setattr(programs, "load_connector_catalog", tracked)
    controls = [
        {
            "control_id": key,
            "framework": "SOC 2",
            "title": key,
            "owner": "security",
            "status": "not_evaluated",
            "evidence_count": 0,
        }
        for key in ("SOC2-CC6.1", "SOC2-CC6.2")
    ]
    programs.build_control_tests([], controls)
    assert len(loads) == 1
