"""Shared response shaping and pagination for authenticated server routes."""

from __future__ import annotations

from pathlib import Path

from fastapi import HTTPException, Request, status

from security_lakehouse import api_v1
from security_lakehouse.auth.rbac import Identity
from security_lakehouse.data_policy import redact_payload
from security_lakehouse.db.base import DEFAULT_PAGE_LIMIT, clamp_limit


def _params(request: Request) -> dict[str, list[str]]:
    """Convert Starlette's query multidict into the ``api_v1`` param shape."""
    params: dict[str, list[str]] = {}
    for key, value in request.query_params.multi_items():
        params.setdefault(key, []).append(value)
    return params


def _pagination(params: dict[str, list[str]]) -> tuple[int, int]:
    """Read ``limit``/``offset`` query params, clamped to a safe page window.

    A missing/invalid ``limit`` defaults to ``DEFAULT_PAGE_LIMIT`` so list
    endpoints are always bounded; an oversized one is capped server-side.
    """
    limit_raw = api_v1.first_param(params, "limit")
    offset_raw = api_v1.first_param(params, "offset")
    limit = clamp_limit(int(limit_raw)) if limit_raw and limit_raw.lstrip("-").isdigit() else DEFAULT_PAGE_LIMIT
    offset = int(offset_raw) if offset_raw and offset_raw.isdigit() else 0
    return limit, max(0, offset)


def _page_window(params: dict[str, list[str]], *, maximum: int = 1000) -> tuple[int, int]:
    """Read ``limit``/``offset``/``cursor`` with the evidence/controls contract.

    A malformed or out-of-range value is a 400 rather than a silent default.
    ``maximum`` lowers the served page size for database-backed lists; the
    applied value is what ``meta.limit`` reports.
    """
    try:
        _rows, limit, offset = api_v1.paginate_collection([], params)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return min(limit, maximum), offset


def _applied_filters(**values: str | None) -> dict[str, list[str]]:
    return {name: [value] for name, value in values.items() if value}


def _page_meta(limit: int, offset: int, count: int) -> dict[str, int]:
    """Envelope ``meta`` fields describing the returned page."""
    return {"count": count, "limit": limit, "offset": offset}


def _portable_references(payload: object) -> object:
    if isinstance(payload, list):
        return [_portable_references(value) for value in payload]
    if isinstance(payload, dict):
        return {
            key: Path(value).name
            if key.endswith("_path") and isinstance(value, str) and Path(value).is_absolute()
            else _portable_references(value)
            for key, value in payload.items()
        }
    return payload


def _redact_payload(payload: object, identity: Identity) -> object:
    return _portable_references(redact_payload(payload, role=identity.role))
