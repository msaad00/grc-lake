from fastapi.testclient import TestClient

from security_lakehouse.io import read_jsonl
from security_lakehouse.server_app import create_app


def test_anonymous_denial_is_operator_private_and_does_not_record_path_secrets(tmp_path):
    client = TestClient(create_app(tmp_path, require_auth=True))
    client.get("/api/v1/trust-shares/secret-bearer-token")
    assert not (tmp_path / "gold/request_audit.jsonl").exists()
    rows = read_jsonl(tmp_path / "server/security_audit/gold/request_audit.jsonl")
    assert rows and rows[0]["actor"] == "anonymous"
    assert "secret-bearer-token" not in str(rows)
