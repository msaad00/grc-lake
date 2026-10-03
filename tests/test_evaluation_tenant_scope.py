"""Platform identity must not be confused with source account identity."""
from pathlib import Path

import pytest

from security_lakehouse.execution_mode import server_execution
from security_lakehouse.io import read_json, read_jsonl
from security_lakehouse.lake_eval import run_lake_eval
from security_lakehouse.pipeline import normalize_raw_events, run_pipeline, run_pipeline_incremental
from security_lakehouse.scale_synthesis import write_audit_scale_fixture
from security_lakehouse.sinks import land_if_configured


def seed(lake: Path) -> Path:
    raw = lake / 'raw' / 'connector_events.jsonl'
    raw.parent.mkdir(parents=True)
    write_audit_scale_fixture(raw, 2, controls_per_event=1, open_ratio=0.0, seed=42)
    return raw


@pytest.mark.parametrize('runner', [run_pipeline, run_pipeline_incremental, normalize_raw_events])
def test_server_pipeline_attributes_authenticated_platform_tenant(tmp_path, runner):
    lake = tmp_path / 'lake'
    raw = seed(lake)
    source_ids = {row['tenant_id'] for row in read_jsonl(raw)}
    with server_execution('platform-a'):
        result = runner(raw, lake)
    assert read_json(Path(result.output_dir) / 'manifest.json')['tenant_id'] == 'platform-a'
    assert {row['tenant_id'] for row in read_jsonl(Path(result.output_dir) / 'silver/normalized_events.jsonl')} == source_ids


@pytest.mark.parametrize('runner', [run_pipeline, run_pipeline_incremental, normalize_raw_events])
@pytest.mark.parametrize('context,requested', [('platform-a', 'platform-b'), (None, None)])
def test_rejects_unbound_or_conflicting_server_scope_before_publication(tmp_path, runner, context, requested):
    lake = tmp_path / 'lake'
    raw = seed(lake)
    with server_execution(context), pytest.raises(ValueError, match='tenant'):
        runner(raw, lake, tenant_id=requested)
    assert not (lake / 'manifest.json').exists()


def test_hosted_daemon_uses_tenant_lake_path(tmp_path, monkeypatch):
    monkeypatch.setenv('TRUSTOPS_COMMERCIAL_HOSTED', '1')
    lake = tmp_path / 'tenants/platform-a'
    raw = seed(lake)
    result = normalize_raw_events(raw, lake)
    assert read_json(Path(result.output_dir) / 'manifest.json')['tenant_id'] == 'platform-a'


def test_hosted_eval_does_not_use_process_sink_settings(tmp_path, monkeypatch):
    lake = tmp_path / 'lake'
    seed(lake)
    monkeypatch.setattr('security_lakehouse.lake_scale.WAREHOUSE_ROW_THRESHOLD', 1)
    target = tmp_path / 'shared.duckdb'
    monkeypatch.setenv('TRUSTOPS_DUCKDB_PATH', str(target))
    with server_execution('platform-a'):
        result = run_lake_eval(lake)
    assert result.mode == 'warehouse_required'
    assert result.result == 'error'
    assert not target.exists()


def test_sink_dispatch_refuses_server_credentials_even_if_explicit(tmp_path):
    target = tmp_path / 'shared.duckdb'
    with server_execution('platform-a'), pytest.raises(ValueError, match='tenant'):
        land_if_configured(tmp_path, {'TRUSTOPS_DUCKDB_PATH': str(target)})
    assert not target.exists()


def test_authenticated_eval_ignores_body_tenant_and_actor(tmp_path):
    from fastapi.testclient import TestClient
    from security_lakehouse.db.base import session_scope
    from security_lakehouse.db.repository import create_api_key, create_tenant, create_user
    from security_lakehouse.server_app import create_app
    app = create_app(tmp_path)
    with session_scope(app.state.sessionmaker) as session:
        tenant = create_tenant(session, slug='acme', name='Acme')
        tenant_id = tenant.id
        user = create_user(session, tenant_id=tenant_id, email='admin@example.test', role='security_admin')
        _, token = create_api_key(session, tenant_id=tenant_id, user_id=user.id)
    lake = tmp_path / 'tenants' / tenant_id
    seed(lake)
    with TestClient(app) as client:
        response = client.post('/api/v1/ingestion/eval', json={'tenant_id': 'spoofed', 'actor': 'spoofed'}, headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 201, response.text
    assert read_json(lake / 'manifest.json')['tenant_id'] == tenant_id
    from security_lakehouse.lake_eval import list_eval_runs
    assert list_eval_runs(lake)[0]['actor'] == 'admin@example.test'


def test_server_connector_materialization_does_not_inherit_sink(tmp_path, monkeypatch):
    from security_lakehouse.connector_runner import _materialize_after_sync
    from security_lakehouse.lake_scale import LakeEvalError
    raw = seed(tmp_path)
    target = tmp_path / 'ambient.duckdb'
    monkeypatch.setenv('TRUSTOPS_DUCKDB_PATH', str(target))
    monkeypatch.setattr('security_lakehouse.lake_scale.WAREHOUSE_ROW_THRESHOLD', 1)
    with server_execution('platform-a'), pytest.raises(LakeEvalError):
        _materialize_after_sync(tmp_path, raw, connector_id='github-security')
    assert not target.exists()


def test_local_eval_keeps_explicit_tenant(tmp_path):
    seed(tmp_path)
    result = run_lake_eval(tmp_path, tenant_id='operator-tenant', env={})
    assert result.result == 'ok'
    assert read_json(tmp_path / 'manifest.json')['tenant_id'] == 'operator-tenant'
