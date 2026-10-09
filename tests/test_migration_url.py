"""Migration configuration preserves URLs instead of interpolating credentials."""

from urllib.parse import quote

import pytest
from sqlalchemy.engine import URL, make_url

from security_lakehouse.db import migrate


@pytest.mark.parametrize(
    "password", ["example@value", "example%value", "example:value", "example/value", "%(name)s", "ordinary"]
)
def test_config_preserves_encoded_password(password):
    url = URL.create(
        "postgresql+psycopg", username="example", password=password, host="db.example.test", database="state"
    )
    rendered = url.render_as_string(hide_password=False)
    configured = migrate._config(rendered).get_main_option("sqlalchemy.url")
    assert configured == rendered
    assert make_url(configured).password == password


def test_config_preserves_encoded_query_parameters():
    url = "postgresql+psycopg:///state?host=" + quote("/tmp/example socket", safe="")
    configured = migrate._config(url).get_main_option("sqlalchemy.url")
    assert configured == url
    assert make_url(configured).query["host"] == "/tmp/example socket"


def test_upgrade_and_current_with_percent_in_lake_path(tmp_path, monkeypatch):
    monkeypatch.delenv("GRC_LAKE_DATABASE_URL", raising=False)
    lake = tmp_path / "tenant%40example"
    migrated = migrate.upgrade(lake)
    revision = migrate.current(lake)
    assert "%40" in migrated
    assert "(head)" in revision


def test_server_starts_with_percent_in_lake_path(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from security_lakehouse.server_app import create_app

    monkeypatch.delenv("GRC_LAKE_DATABASE_URL", raising=False)
    app = create_app(tmp_path / "tenant%example", require_auth=False)
    with TestClient(app) as client:
        response = client.get("/api/healthz")
    assert response.status_code == 200
