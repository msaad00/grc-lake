"""A sink projection must recover without mixing runs or lake owners."""
import json
from pathlib import Path

import pytest

from security_lakehouse.sinks.duckdb_sink import DuckDBSink, DuckDBSinkConfig
from test_duckdb_sink import _seed_lake

duckdb = pytest.importorskip('duckdb')


def test_failed_refresh_rolls_back_every_table(tmp_path):
    lake = _seed_lake(tmp_path)
    db = tmp_path / 'sink.duckdb'
    sink = DuckDBSink(DuckDBSinkConfig(str(db)))
    sink.load(lake)
    (lake / 'silver/normalized_events.jsonl').write_text(json.dumps({'event_id': 'new', 'tenant_id': 'source'}) + '\n')
    (lake / 'gold/asset_risk.jsonl').write_text(json.dumps({'asset_id': 'bad', 'latest_event_time': 'not-a-date'}) + '\n')
    with pytest.raises(ValueError):
        sink.load(lake)
    with duckdb.connect(str(db)) as conn:
        assert conn.execute('select event_id from normalized_events order by event_id').fetchall() == [('aws-1',), ('azure-1',)]
        assert conn.execute('select asset_id from asset_risk').fetchall() == [('aws:account:1',)]
    (lake / 'gold/asset_risk.jsonl').write_text('')
    sink.load(lake)
    with duckdb.connect(str(db)) as conn:
        assert conn.execute('select event_id from normalized_events').fetchall() == [('new',)]
        assert conn.execute('select count(*) from asset_risk').fetchone() == (0,)


def test_different_lake_cannot_overwrite_same_destination(tmp_path):
    a, b = tmp_path / 'a', tmp_path / 'b'
    a.mkdir(); b.mkdir()
    _seed_lake(a); _seed_lake(b)
    sink = DuckDBSink(DuckDBSinkConfig(str(tmp_path / 'sink.duckdb')))
    sink.load(a)
    with pytest.raises(ValueError, match='owner'):
        sink.load(b)


def test_missing_artifact_cannot_erase_valid_projection(tmp_path):
    lake = _seed_lake(tmp_path)
    db = tmp_path / 'sink.duckdb'
    sink = DuckDBSink(DuckDBSinkConfig(str(db)))
    sink.load(lake)
    (lake / 'gold/asset_risk.jsonl').unlink()
    with pytest.raises(FileNotFoundError):
        sink.load(lake)
    with duckdb.connect(str(db)) as conn:
        assert conn.execute('select count(*) from normalized_events').fetchone() == (2,)


def test_existing_unowned_tables_require_new_destination(tmp_path):
    lake = _seed_lake(tmp_path)
    db = tmp_path / 'sink.duckdb'
    with duckdb.connect(str(db)) as conn:
        conn.execute('create table normalized_events (event_id varchar)')
        conn.execute("insert into normalized_events values ('legacy')")
    with pytest.raises(ValueError, match='unowned'):
        DuckDBSink(DuckDBSinkConfig(str(db))).load(lake)
    with duckdb.connect(str(db)) as conn:
        assert conn.execute('select * from normalized_events').fetchall() == [('legacy',)]


def test_injected_connection_requires_no_active_transaction(tmp_path):
    lake = _seed_lake(tmp_path)
    with duckdb.connect(':memory:') as conn:
        conn.execute('create table caller_data (value integer)')
        conn.execute('begin')
        conn.execute('insert into caller_data values (42)')
        with pytest.raises(duckdb.TransactionException):
            DuckDBSink(DuckDBSinkConfig(':memory:'), connection=conn).load(lake)
        # DuckDB aborts nested BEGIN itself. The sink must not claim ownership
        # of that transaction or commit it; its owner must explicitly rollback.
        with pytest.raises(duckdb.TransactionException, match='aborted'):
            conn.execute('select * from caller_data')
        conn.execute('rollback')
        assert conn.execute('select * from caller_data').fetchall() == []


def test_generation_exports_keep_one_owner_and_platform_identity(tmp_path):
    from security_lakehouse.pipeline import run_pipeline
    from security_lakehouse.scale_synthesis import write_audit_scale_fixture
    raw = tmp_path / 'raw.jsonl'
    write_audit_scale_fixture(raw, 2, controls_per_event=1, open_ratio=0.0, seed=7)
    lake = tmp_path / 'lake'
    sink = DuckDBSink(DuckDBSinkConfig(str(tmp_path / 'sink.duckdb')))
    first = run_pipeline(raw, lake, tenant_id='platform-a')
    sink.load(first.output_dir)
    second = run_pipeline(raw, lake, tenant_id='platform-a')
    sink.load(second.output_dir)
    sink.load(lake)
    with duckdb.connect(str(tmp_path / 'sink.duckdb')) as conn:
        assert conn.execute('select distinct tenant_id from control_posture').fetchall() == [('platform-a',)]
        assert conn.execute('select count(*) from normalized_events').fetchone() == (2,)


def test_other_connection_sees_previous_projection_until_commit(tmp_path):
    lake = _seed_lake(tmp_path)
    db = str(tmp_path / 'sink.duckdb')
    DuckDBSink(DuckDBSinkConfig(db)).load(lake)
    (lake / 'silver/normalized_events.jsonl').write_text(json.dumps({'event_id': 'new', 'tenant_id': 'source'}) + '\n')
    with duckdb.connect(db) as writer, duckdb.connect(db) as reader:
        class ObservedConnection:
            def execute(self, *args):
                return writer.execute(*args)
            def executemany(self, *args):
                result = writer.executemany(*args)
                assert reader.execute('select event_id from normalized_events order by event_id').fetchall() == [('aws-1',), ('azure-1',)]
                return result
        DuckDBSink(DuckDBSinkConfig(db), connection=ObservedConnection()).load(lake)
        assert reader.execute('select event_id from normalized_events').fetchall() == [('new',)]
