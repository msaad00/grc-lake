"""Shared FastAPI dependencies and request helpers for server routers."""

from __future__ import annotations

from datetime import datetime

from fastapi import HTTPException, Request, status

from security_lakehouse.auth.rbac import Identity
from security_lakehouse.data_policy import redact_payload
from security_lakehouse.db.base import DEFAULT_PAGE_LIMIT, clamp_limit


def parse_dt(value: str | None) -> datetime | None:
    if value is None or value == "":
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid datetime: {value!r}") from exc


def query_params(request: Request) -> dict[str, list[str]]:
    """Convert Starlette's query multidict into the ``api_v1`` param shape."""
    params: dict[str, list[str]] = {}
    for key, value in request.query_params.multi_items():
        params.setdefault(key, []).append(value)
    return params


def pagination(params: dict[str, list[str]]) -> tuple[int, int]:
    """Read ``limit``/``offset`` query params, clamped to a safe page window."""
    limit_raw = (params.get("limit") or [None])[0]
    offset_raw = (params.get("offset") or [None])[0]
    limit = clamp_limit(int(limit_raw)) if limit_raw and limit_raw.lstrip("-").isdigit() else DEFAULT_PAGE_LIMIT
    offset = int(offset_raw) if offset_raw and offset_raw.isdigit() else 0
    return limit, max(0, offset)


def page_meta(limit: int, offset: int, count: int) -> dict[str, int]:
    return {"count": count, "limit": limit, "offset": offset}


def redact_for_identity(payload: object, identity: Identity) -> object:
    return redact_payload(payload, role=identity.role)
