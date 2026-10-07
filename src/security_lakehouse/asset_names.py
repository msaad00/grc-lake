"""Human-readable asset names, kept alongside (never instead of) asset IDs.

A raw event may name its asset in ``entity.asset_name``. The name is display
data only: every join and key still uses ``asset_id``. Names live on the gold
asset rows (``gold/asset_risk.jsonl``) rather than on normalized events, so the
``trustops.normalized_event.v1`` contract (and its Parquet and Iceberg exports)
is unchanged; read paths that show assets attach the name from there.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

from security_lakehouse.projected_reads import read_projection


def entity_asset_id(entity: dict[str, Any]) -> str:
    """The asset ID normalization assigns to a raw event's entity."""
    return str(entity.get("asset_id") or entity.get("id") or entity.get("name") or "unknown")


def asset_names_from_raw(raw_rows: Iterable[dict[str, Any]]) -> dict[str, str]:
    """Map asset ID to the first non-empty ``entity.asset_name`` seen for it."""
    names: dict[str, str] = {}
    for row in raw_rows:
        entity = row.get("entity")
        if not isinstance(entity, dict):
            continue
        name = str(entity.get("asset_name") or "").strip()
        if name:
            names.setdefault(entity_asset_id(entity), name)
    return names


def load_asset_names(lake_dir: str | Path) -> dict[str, str]:
    """Asset ID to name, from the gold asset rows of a lake."""
    lake = Path(lake_dir)
    rows = read_projection(
        lake / "gold" / "asset_risk.jsonl", ("asset_id", "asset_name"), missing_ok=True, base_dir=lake
    )
    return {
        str(row["asset_id"]): str(row["asset_name"]) for row in rows if row.get("asset_id") and row.get("asset_name")
    }


def with_asset_names(rows: list[dict[str, Any]], names: dict[str, str]) -> list[dict[str, Any]]:
    """Copy ``rows``, adding ``asset_name`` wherever the row's asset has one."""
    if not names:
        return rows
    out: list[dict[str, Any]] = []
    for row in rows:
        name = names.get(str(row.get("asset_id") or ""))
        out.append({**row, "asset_name": name} if name and not row.get("asset_name") else row)
    return out
