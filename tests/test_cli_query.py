"""`grc-lake query`: read-only SQL against the local marts."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from security_lakehouse import cli

duckdb = pytest.importorskip("duckdb")

ENGINES = ("sqlite", "duckdb")


def _lake(tmp_path: Path) -> Path:
    mart = tmp_path / "lake" / "mart"
    mart.mkdir(parents=True)
    with sqlite3.connect(mart / "security_lakehouse.sqlite") as conn:
        conn.execute("CREATE TABLE controls (control_id TEXT, status TEXT)")
        conn.executemany("INSERT INTO controls VALUES (?, ?)", [("C-1", "pass"), ("C-2", "fail")])
    with duckdb.connect(str(mart / "security_data_lake.duckdb")) as conn:
        conn.execute("CREATE TABLE controls (control_id VARCHAR, status VARCHAR)")
        conn.execute("INSERT INTO controls VALUES ('C-1', 'pass'), ('C-2', 'fail')")
    return tmp_path / "lake"


def _rows(lake: Path, engine: str) -> int:
    mart = lake / "mart"
    if engine == "sqlite":
        with sqlite3.connect(mart / "security_lakehouse.sqlite") as conn:
            return int(conn.execute("SELECT count(*) FROM controls").fetchone()[0])
    with duckdb.connect(str(mart / "security_data_lake.duckdb"), read_only=True) as conn:
        return int(conn.execute("SELECT count(*) FROM controls").fetchone()[0])


def _query(lake: Path, engine: str, sql: str) -> int:
    return cli._query(cli._parser().parse_args(["query", "--lake", str(lake), "--engine", engine, sql]))


@pytest.mark.parametrize("engine", ENGINES)
def test_common_table_expression_is_allowed(tmp_path: Path, engine: str, capsys: pytest.CaptureFixture[str]) -> None:
    lake = _lake(tmp_path)
    sql = "WITH failing AS (SELECT control_id FROM controls WHERE status = 'fail') SELECT control_id FROM failing"
    assert _query(lake, engine, sql) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["rows"] == [{"control_id": "C-2"}]


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1; DROP TABLE controls",
        "WITH x AS (SELECT 1) SELECT 1; DROP TABLE controls",
        "WITH gone AS (SELECT control_id FROM controls) DELETE FROM controls",
        "with gone as (select 1) insert into controls values ('C-3', 'pass')",
    ],
)
def test_writes_are_refused_even_behind_select_or_with(tmp_path: Path, engine: str, sql: str) -> None:
    lake = _lake(tmp_path)
    with pytest.raises(Exception):  # noqa: B017 - engine-specific error types; the invariant is below
        _query(lake, engine, sql)
    assert _rows(lake, engine) == 2


@pytest.mark.parametrize("sql", ["DROP TABLE controls", "PRAGMA writable_schema = 1", "  delete from controls"])
def test_non_select_statements_are_rejected_before_execution(tmp_path: Path, sql: str) -> None:
    lake = _lake(tmp_path)
    with pytest.raises(ValueError, match="SELECT"):
        _query(lake, "sqlite", sql)
    assert _rows(lake, "sqlite") == 2


def test_missing_sqlite_mart_is_not_created(tmp_path: Path) -> None:
    lake = tmp_path / "empty-lake"
    (lake / "mart").mkdir(parents=True)
    with pytest.raises(sqlite3.OperationalError):
        _query(lake, "sqlite", "SELECT 1")
    assert not (lake / "mart" / "security_lakehouse.sqlite").exists()


def test_install_hints_name_the_published_distribution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError) as missing_mart:
        cli._query_duckdb(tmp_path / "absent.duckdb", "SELECT 1")
    assert "pip install 'grc-lake[analytics]'" in str(missing_mart.value)
    assert "uv sync --extra analytics" in str(missing_mart.value)
    assert "pip install -e" not in str(missing_mart.value)

    mart = tmp_path / "present.duckdb"
    mart.write_bytes(b"")
    monkeypatch.setitem(__import__("sys").modules, "duckdb", None)
    with pytest.raises(ValueError) as missing_module:
        cli._query_duckdb(mart, "SELECT 1")
    assert "pip install 'grc-lake[analytics]'" in str(missing_module.value)
    assert "pip install -e" not in str(missing_module.value)
