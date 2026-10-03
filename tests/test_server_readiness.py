"""Readiness checks dependencies while liveness only checks the process."""

from fastapi.testclient import TestClient

from security_lakehouse.server_app import create_app


def test_empty_bootstrap_is_ready_and_probes_do_not_write_audit(tmp_path):
    with TestClient(create_app(tmp_path)) as client:
        for _ in range(3):
            response = client.get("/api/readyz")
            assert response.status_code == 200
            assert response.json() == {"ok": True, "service": "trustops-assessment"}
            assert response.headers["cache-control"] == "no-store"
    assert not list(tmp_path.glob(".readiness-*"))
    assert not list(tmp_path.rglob("*request*audit*.jsonl"))


def test_missing_database_is_unready_without_recreating_it(tmp_path):
    with TestClient(create_app(tmp_path)) as client:
        assert client.get("/api/readyz").status_code == 200
        database = tmp_path / "server/app.db"
        backup = database.with_suffix(".saved")
        database.rename(backup)
        response = client.get("/api/readyz")
        assert response.status_code == 503
        assert response.json() == {"ok": False, "service": "trustops-assessment"}
        assert not database.exists()
        assert client.get("/api/healthz").status_code == 200
        backup.rename(database)
        assert client.get("/api/readyz").status_code == 200


def test_corrupt_same_inode_database_is_unready_then_recovers(tmp_path):
    with TestClient(create_app(tmp_path)) as client:
        assert client.get("/api/readyz").status_code == 200
        database = tmp_path / "server/app.db"
        original = database.read_bytes()
        database.write_bytes(b"not a database")
        assert client.get("/api/readyz").status_code == 503
        database.write_bytes(original)
        assert client.get("/api/readyz").status_code == 200


def test_unwritable_lake_is_unready_without_leaking_error(tmp_path, monkeypatch):
    with TestClient(create_app(tmp_path)) as client:

        def denied(*args, **kwargs):
            raise PermissionError("private/path/secret")

        monkeypatch.setattr("tempfile.TemporaryFile", denied)
        response = client.get("/api/readyz")
        assert response.status_code == 503
        assert "private" not in response.text
        assert client.get("/api/healthz").status_code == 200


def test_helm_uses_readiness_endpoint():
    import yaml

    from test_helm_security import _helm_template

    result = _helm_template()
    assert result.returncode == 0
    deployment = next(d for d in yaml.safe_load_all(result.stdout) if d and d["kind"] == "Deployment")
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    assert container["readinessProbe"]["httpGet"]["path"] == "/api/readyz"
    assert container["livenessProbe"]["httpGet"]["path"] == "/api/healthz"
