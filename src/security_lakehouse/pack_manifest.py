"""Generic JSON-manifest-driven framework pack builder.

Framework packs used to be bespoke Python functions: one ``*_specs()``
function per framework in ``framework_packs.py``, hard-coding every
identifier, title, and source citation inline. That made routine work (e.g.
adding a new framework, or reviewing/auditing identifiers) unnecessarily
expensive, because there was no declarative data to diff, validate, or
generate against.

This module inverts that: a framework pack's *data* (control/criterion
identifiers, titles, and the pinned source citation) lives in a JSON
manifest file under ``frameworks/packs/data/``; a small, named, shared
*transform* function (still code, per framework) turns each manifest row
into a :class:`~security_lakehouse.pack_spec.PackControlSpec` — handling
whatever framework-specific logic doesn't belong in data: ID normalization,
risk-domain/owner lookups, evidence-requirement wording, and so on.

See ``docs/FRAMEWORK_PACKS.md`` for the manifest schema reference and the
"add a new framework" workflow.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from security_lakehouse.jsontypes import JsonObject
from security_lakehouse.pack_spec import PackControlSpec

PACK_MANIFEST_SCHEMA = "trustops.framework_pack_manifest.v1"


@dataclass(frozen=True)
class PackManifestRow:
    """One control/criterion identifier from a manifest.

    ``extra`` carries any framework-specific fields beyond ``id``/``title``
    (e.g. a limited pack's per-row ``risk_domain``/``owner``/``asset_types``,
    or CMMC's ``sprs_points``/``poam_eligible``) through to the transform
    function untouched.
    """

    id: str
    title: str
    extra: JsonObject = field(default_factory=dict)


@dataclass(frozen=True)
class PackManifest:
    """A parsed framework pack manifest: source citation + ordered rows."""

    path: Path
    schema: str
    source: JsonObject
    rows: tuple[PackManifestRow, ...]


def load_pack_manifest(
    manifest_path: Path,
    *,
    rows_key: str = "rows",
    id_field: str = "id",
    title_field: str = "title",
) -> PackManifest:
    """Load a framework pack manifest JSON file.

    ``rows_key`` selects the top-level key holding the control rows, which
    may be shaped as:

    - a JSON object mapping identifier -> title (the ``nist_csf_2_core.json``
      precedent's ``"outcomes"`` shape, e.g. ``{"GV.OC-01": "..."}``);
    - a JSON array of objects (``[{"id": ..., "title": ...}, ...]`` — the
      default new-manifest shape, also matches existing pack data files like
      ``cis_aws_v3.json``'s ``"requirements"`` array); or
    - a JSON array of plain identifier strings (e.g.
      ``nist_800_53_rev5_moderate.json``'s ``"control_ids"``), for
      frameworks with no distinct per-ID title text.

    ``id_field``/``title_field`` name the object keys to read for the array-
    of-objects shape, so this loader can read pre-existing pack data files
    (which other modules, e.g. ``sprs.py``, also read directly) without
    requiring them to be renamed or restructured.
    """
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw_rows = payload[rows_key]
    rows: list[PackManifestRow] = []
    if isinstance(raw_rows, dict):
        for row_id, title in raw_rows.items():
            rows.append(PackManifestRow(id=str(row_id), title=str(title)))
    else:
        for entry in raw_rows:
            if isinstance(entry, str):
                rows.append(PackManifestRow(id=entry, title=""))
                continue
            extra = {key: value for key, value in entry.items() if key not in (id_field, title_field)}
            rows.append(
                PackManifestRow(
                    id=str(entry[id_field]),
                    title=str(entry.get(title_field, "")),
                    extra=extra,
                )
            )
    raw_source = payload.get("source", {})
    # Some pre-existing pack data files (e.g. cis_aws_v3.json) carry "source"
    # as a plain citation string with a sibling "official_source_url" key,
    # rather than the nist_csf_2_core.json precedent's {"url": ..., ...}
    # object. Normalize either shape to an object so callers have one type.
    source = raw_source if isinstance(raw_source, dict) else ({"name": raw_source} if raw_source else {})
    if "official_source_url" in payload and "url" not in source:
        source = {**source, "url": payload["official_source_url"]}
    return PackManifest(
        path=manifest_path,
        schema=str(payload.get("schema", "")),
        source=source,
        rows=tuple(rows),
    )


def pack_from_manifest(
    manifest_path: Path,
    *,
    transform: Callable[[PackManifestRow], PackControlSpec],
    rows_key: str = "rows",
    id_field: str = "id",
    title_field: str = "title",
) -> list[PackControlSpec]:
    """Build a framework pack's control specs from a JSON manifest.

    ``transform`` receives each :class:`PackManifestRow` and returns the
    finished :class:`PackControlSpec`. The manifest supplies the *data*
    (identifiers, titles, source citation); ``transform`` supplies the
    *logic* — this replaces a full bespoke ``*_specs()`` function per
    framework with one small, named, shared transform per framework.
    """
    manifest = load_pack_manifest(manifest_path, rows_key=rows_key, id_field=id_field, title_field=title_field)
    return [transform(row) for row in manifest.rows]
