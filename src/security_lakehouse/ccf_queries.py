"""Generation-scoped CCF projections with bounded page materialization."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any

from security_lakehouse.generations import generation_reader, pinned_path
from security_lakehouse.io import read_json, resolve_path

PROJECTION_VERSION = 1
SCALARS = ("safeguard_id", "source_tenant_id", "asset_id", "status")
ARRAYS = ("event_ids", "evidence_hashes", "reasons")
FIELDS = SCALARS + ARRAYS


class CcfReadError(ValueError):
    """A declared projection is missing, incompatible, or unreadable."""


def write_projection(connection: sqlite3.Connection, assessment: dict[str, Any]) -> None:
    summary = {key: value for key, value in assessment.items() if key != "asset_results"}
    summary["asset_result_count"] = len(assessment["asset_results"])
    connection.execute("CREATE TABLE ccf_summary (payload TEXT NOT NULL)")
    connection.execute("INSERT INTO ccf_summary VALUES (?)", (json.dumps(summary),))
    columns = ", ".join(f"{field} TEXT NOT NULL" for field in FIELDS)
    sorts = ", ".join(f"{field}_sort TEXT NOT NULL" for field in ARRAYS)
    connection.execute(
        f"CREATE TABLE ccf_asset_results (ordinal INTEGER PRIMARY KEY, {columns}, {sorts}, payload TEXT NOT NULL)"
    )
    placeholders = ",".join("?" for _ in range(2 + len(FIELDS) + len(ARRAYS)))
    connection.executemany(
        f"INSERT INTO ccf_asset_results VALUES ({placeholders})",
        (
            (
                ordinal,
                *(row[key] for key in SCALARS),
                *(json.dumps(row[key]) for key in ARRAYS),
                *(str(row[key]) for key in ARRAYS),
                json.dumps(row),
            )
            for ordinal, row in enumerate(assessment["asset_results"])
        ),
    )
    for field in SCALARS:
        connection.execute(f"CREATE INDEX ccf_by_{field} ON ccf_asset_results ({field}, ordinal)")


@contextmanager
def _projection(lake: Path):
    try:
        lake = resolve_path(lake)
        expected = pinned_path(lake / "mart/security_lakehouse.sqlite").absolute()
        path = resolve_path(expected, base_dir=lake)
        manifest = resolve_path(expected.parent.parent / "generation.json", base_dir=lake)
        version = read_json(manifest).get("ccf_projection_version") if manifest.is_file() else None
        if version is None:
            yield None  # Older generations retain the original JSON read contract.
            return
        if path != expected:
            raise CcfReadError("CCF projection redirects outside its pinned generation")
        if version != PROJECTION_VERSION:
            raise CcfReadError("unsupported CCF projection")
        with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)) as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA cache_size=-1024")
            connection.execute("PRAGMA temp_store=FILE")
            connection.execute("BEGIN")
            yield connection
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise CcfReadError("CCF assessment projection is unavailable") from exc


@generation_reader
def read_summary(lake: Path) -> dict[str, Any] | None:
    with _projection(lake) as connection:
        if connection is None:
            return None
        row = connection.execute("SELECT payload FROM ccf_summary").fetchone()
        if row is None:
            raise CcfReadError("missing CCF summary")
        return json.loads(row[0])


@generation_reader
def read_page(
    lake: Path,
    *,
    filters: dict[str, list[str]],
    sort: str | None,
    limit: int,
    offset: int,
) -> tuple[list[dict[str, Any]], int] | None:
    """Read one page plus its exact filtered count in one immutable generation.

    Values are parameterized; column names come only from the fixed allowlist.
    Array membership and list ordering preserve the existing Python contract.
    """
    if not 1 <= limit <= 1000 or offset < 0:
        raise ValueError("invalid page bounds")
    clauses = []
    parameters: list[str | int] = []
    for field, expected in filters.items():
        if field not in FIELDS or not expected:
            clauses.append("0")
            continue
        placeholders = "SELECT value FROM json_each(?)"
        if field in ARRAYS:
            clauses.append(f"EXISTS (SELECT 1 FROM json_each({field}) WHERE value IN ({placeholders}))")
        else:
            clauses.append(f"{field} IN ({placeholders})")
        parameters.append(json.dumps(expected))
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    field = (sort[1:] if sort.startswith("-") else sort) if sort else ""
    direction = "DESC" if sort and sort.startswith("-") else "ASC"
    order = f"{field + '_sort' if field in ARRAYS else field} {direction}, ordinal" if field in FIELDS else "ordinal"
    with _projection(lake) as connection:
        if connection is None:
            return None
        count = connection.execute(f"SELECT count(*) FROM ccf_asset_results{where}", parameters).fetchone()[0]
        rows = connection.execute(
            f"SELECT payload FROM ccf_asset_results{where} ORDER BY {order} LIMIT ? OFFSET ?",
            [*parameters, limit, min(offset, 2**63 - 1)],
        )
        return [json.loads(row[0]) for row in rows], count
