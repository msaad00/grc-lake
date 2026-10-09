"""Typed Python client over the ``/api/v1`` surface (BR-5).

Agents and scripts should reach TrustOps through the *same* contract a human
console uses -- the versioned ``/api/v1`` envelope ``{data, meta, errors}``.
This module ships :class:`TrustOpsClient`, a thin synchronous wrapper around
``httpx.Client`` that:

- attaches the ``Authorization: Bearer <api_key>`` header,
- parses the v1 envelope and returns the unwrapped ``data``,
- raises a typed :class:`TrustOpsError` carrying the envelope ``errors`` on any
  non-2xx response.

The client lives behind the optional ``sdk`` extra::

    pip install 'trustops-security-data-lake[sdk]'

``httpx`` is imported lazily inside the client so ``import
security_lakehouse.sdk`` never hard-requires it -- only constructing a
:class:`TrustOpsClient` does.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from security_lakehouse.jsontypes import JsonObject

if TYPE_CHECKING:  # pragma: no cover - typing only
    import httpx


class TrustOpsError(RuntimeError):
    """Raised when the API returns a non-2xx response.

    The structured v1 ``errors`` list (each entry a ``{"code", "detail"}``
    mapping) is preserved on :attr:`errors`, and the HTTP status on
    :attr:`status_code`, so callers can branch on machine-readable codes rather
    than scraping the message string.
    """

    def __init__(self, status_code: int, errors: list[JsonObject]) -> None:
        self.status_code = status_code
        self.errors = errors
        if errors:
            summary = "; ".join(f"{err.get('code', 'error')}: {err.get('detail', '')}".strip(": ") for err in errors)
        else:
            summary = "request failed"
        super().__init__(f"HTTP {status_code}: {summary}")


def _params(
    *,
    limit: int | None = None,
    offset: int | None = None,
    sort: str | None = None,
    filter: dict[str, Any] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build a query-param dict from the shared collection controls.

    ``filter`` maps ``field -> value`` (mirroring the ``?field=value`` contract
    in :mod:`security_lakehouse.api_v1`); ``extra`` carries resource-specific
    query knobs (e.g. ``status``/``severity``/``owner``). ``None`` values are
    dropped so they never reach the wire.
    """
    params: dict[str, Any] = {}
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if sort is not None:
        params["sort"] = sort
    if filter:
        for key, value in filter.items():
            if value is not None:
                params[key] = value
    for key, value in extra.items():
        if value is not None:
            params[key] = value
    return params


def _parse_envelope(response: httpx.Response) -> Any:
    """Validate status, parse the v1 envelope, and return ``data``.

    Shared by the sync and async clients: both unwrap the same
    ``{data, meta, errors}`` envelope and raise the same
    :class:`TrustOpsError` on any non-2xx response, so the parsing contract
    lives in exactly one place.
    """
    try:
        body = response.json()
    except ValueError:
        body = {}
    if not response.is_success:
        errors = body.get("errors") if isinstance(body, dict) else None
        raise TrustOpsError(response.status_code, errors or [])
    if isinstance(body, dict) and "data" in body:
        return body["data"]
    return body


class TrustOpsClient:
    """Synchronous client for the TrustOps ``/api/v1`` surface.

    Example::

        from security_lakehouse.sdk import TrustOpsClient

        client = TrustOpsClient("https://trustops.example.com", api_key="tops_example_token")
        posture = client.get_posture()
        print(posture["posture"]["score"])

    The client is a context manager and should be closed (or used in a ``with``
    block) to release the underlying connection pool.
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """Create a client.

        Args:
            base_url: Root URL of the TrustOps server (e.g.
                ``https://trustops.example.com``). The ``/api/v1`` prefix is
                added by each method.
            api_key: Bearer token minted via ``/api/v1/auth/keys``. Omit only
                for servers started with ``require_auth=False``.
            timeout: Per-request timeout in seconds.
            transport: Optional ``httpx`` transport, primarily for in-process
                ASGI testing (``httpx.ASGITransport(app=...)``).
        """
        import httpx  # lazy: keeps `import ...sdk` free of the httpx requirement

        headers = {"accept": "application/json"}
        if api_key:
            headers["authorization"] = f"Bearer {api_key}"
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers=headers,
            timeout=timeout,
            transport=transport,
        )

    # --- context manager / lifecycle ---------------------------------------
    def __enter__(self) -> TrustOpsClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._client.close()

    # --- envelope-aware transport ------------------------------------------
    def _unwrap(self, response: httpx.Response) -> Any:
        """Validate status, parse the v1 envelope, and return ``data``."""
        return _parse_envelope(response)

    def _get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        return self._unwrap(self._client.get(path, params=params or None))

    def _post(self, path: str, *, json: JsonObject | None = None) -> Any:
        return self._unwrap(self._client.post(path, json=json or {}))

    def _patch(self, path: str, *, json: JsonObject | None = None) -> Any:
        return self._unwrap(self._client.patch(path, json=json or {}))

    def _delete(self, path: str) -> Any:
        return self._unwrap(self._client.delete(path))

    # --- discovery / posture -----------------------------------------------
    def describe_api(self) -> JsonObject:
        """Return the self-describing v1 contract (resource catalog + controls)."""
        return self._get("/api/v1")

    def get_posture(self) -> JsonObject:
        """Return the current compliance posture (score, frameworks, violations)."""
        return self._get("/api/v1/posture/current")

    def posture_as_of(self, as_of: str) -> JsonObject:
        """Return the posture as of a point in time.

        Selects the newest snapshot whose ``evaluated_at`` is at or before
        ``as_of`` (an ISO date or datetime). The result echoes ``found``,
        ``evaluated_at``, ``assessment_hash``, and ``requested_as_of``.
        """
        return self._get("/api/v1/posture/as-of", params={"as_of": as_of})

    # --- lake-backed read collections --------------------------------------
    def list_controls(
        self,
        *,
        limit: int | None = None,
        offset: int | None = None,
        sort: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> list[JsonObject]:
        """List control posture rows."""
        return self._get("/api/v1/controls", params=_params(limit=limit, offset=offset, sort=sort, filter=filter))

    def list_control_tests(
        self,
        *,
        limit: int | None = None,
        offset: int | None = None,
        sort: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> list[JsonObject]:
        """List control test results."""
        return self._get("/api/v1/control-tests", params=_params(limit=limit, offset=offset, sort=sort, filter=filter))

    def list_evidence(
        self,
        *,
        limit: int | None = None,
        offset: int | None = None,
        sort: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> list[JsonObject]:
        """List normalized evidence events."""
        return self._get("/api/v1/evidence", params=_params(limit=limit, offset=offset, sort=sort, filter=filter))

    def list_assets(
        self,
        *,
        limit: int | None = None,
        offset: int | None = None,
        sort: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> list[JsonObject]:
        """List assets with their risk scores."""
        return self._get("/api/v1/assets", params=_params(limit=limit, offset=offset, sort=sort, filter=filter))

    def list_violations(
        self,
        *,
        limit: int | None = None,
        offset: int | None = None,
        sort: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> list[JsonObject]:
        """List open posture violations."""
        return self._get("/api/v1/violations", params=_params(limit=limit, offset=offset, sort=sort, filter=filter))

    def list_snapshots(
        self,
        *,
        limit: int | None = None,
        offset: int | None = None,
        sort: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> list[JsonObject]:
        """List point-in-time assessment snapshots."""
        return self._get("/api/v1/snapshots", params=_params(limit=limit, offset=offset, sort=sort, filter=filter))

    def create_snapshot(self, reason: str = "api_request") -> JsonObject:
        """Write a new assessment snapshot to the gold zone and return its record."""
        return self._post("/api/v1/snapshots", json={"reason": reason})

    # --- risk register (GRC) -----------------------------------------------
    def list_risks(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        owner: str | None = None,
    ) -> list[JsonObject]:
        """List risk-register entries, optionally filtered by status/severity/owner."""
        return self._get("/api/v1/risks", params=_params(status=status, severity=severity, owner=owner))

    def create_risk(self, **fields: Any) -> JsonObject:
        """Create a risk-register entry (e.g. ``title=``, ``severity=``, ``owner=``)."""
        return self._post("/api/v1/risks", json=dict(fields))

    def get_risk(self, risk_id: str) -> JsonObject:
        """Fetch a single risk by id.

        The server exposes risks as a tenant-scoped collection; this reads the
        list and selects the matching id, raising :class:`TrustOpsError` (404)
        when absent so the method behaves like a direct GET.
        """
        for risk in self.list_risks():
            if risk.get("id") == risk_id:
                return risk
        raise TrustOpsError(404, [{"code": "not_found", "detail": "risk not found"}])

    def update_risk(self, risk_id: str, **fields: Any) -> JsonObject:
        """Patch a risk-register entry; ``fields`` are the columns to change."""
        return self._patch(f"/api/v1/risks/{risk_id}", json=dict(fields))

    def delete_risk(self, risk_id: str) -> JsonObject:
        """Delete a risk-register entry."""
        return self._delete(f"/api/v1/risks/{risk_id}")

    # --- remediation -------------------------------------------------------
    def list_tasks(
        self,
        *,
        status: str | None = None,
        owner: str | None = None,
        overdue: bool | None = None,
    ) -> list[JsonObject]:
        """List remediation tasks, optionally filtered by status/owner/overdue."""
        return self._get("/api/v1/remediation/tasks", params=_params(status=status, owner=owner, overdue=overdue))

    def create_task(self, **fields: Any) -> JsonObject:
        """Create a remediation task (e.g. ``title=``, ``owner=``, ``priority=``)."""
        return self._post("/api/v1/remediation/tasks", json=dict(fields))


class AsyncTrustOpsClient:
    """Asynchronous client for the TrustOps ``/api/v1`` surface.

    Mirrors :class:`TrustOpsClient` on ``httpx.AsyncClient`` -- same
    constructor, same method surface, and the same v1-envelope-unwrap /
    :class:`TrustOpsError` behavior (shared via :func:`_parse_envelope`) -- but
    every request method is a coroutine. Example::

        from security_lakehouse.sdk import AsyncTrustOpsClient

        async with AsyncTrustOpsClient("https://trustops.example.com", api_key="tops_example_token") as client:
            posture = await client.get_posture()
            print(posture["posture"]["score"])

    The client is an async context manager and should be closed (via
    :meth:`aclose`, or an ``async with`` block) to release the connection pool.
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """Create an async client.

        Args:
            base_url: Root URL of the TrustOps server (e.g.
                ``https://trustops.example.com``). The ``/api/v1`` prefix is
                added by each method.
            api_key: Bearer token minted via ``/api/v1/auth/keys``. Omit only
                for servers started with ``require_auth=False``.
            timeout: Per-request timeout in seconds.
            transport: Optional ``httpx`` async transport, primarily for
                in-process ASGI testing (``httpx.ASGITransport(app=...)``).
        """
        import httpx  # lazy: keeps `import ...sdk` free of the httpx requirement

        headers = {"accept": "application/json"}
        if api_key:
            headers["authorization"] = f"Bearer {api_key}"
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers=headers,
            timeout=timeout,
            transport=transport,
        )

    # --- context manager / lifecycle ---------------------------------------
    async def __aenter__(self) -> AsyncTrustOpsClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying HTTP connection pool."""
        await self._client.aclose()

    # alias so callers can mirror the sync ``close()`` name.
    close = aclose

    # --- envelope-aware transport ------------------------------------------
    def _unwrap(self, response: httpx.Response) -> Any:
        """Validate status, parse the v1 envelope, and return ``data``."""
        return _parse_envelope(response)

    async def _get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        return self._unwrap(await self._client.get(path, params=params or None))

    async def _post(self, path: str, *, json: JsonObject | None = None) -> Any:
        return self._unwrap(await self._client.post(path, json=json or {}))

    async def _patch(self, path: str, *, json: JsonObject | None = None) -> Any:
        return self._unwrap(await self._client.patch(path, json=json or {}))

    async def _delete(self, path: str) -> Any:
        return self._unwrap(await self._client.delete(path))

    # --- discovery / posture -----------------------------------------------
    async def describe_api(self) -> JsonObject:
        """Return the self-describing v1 contract (resource catalog + controls)."""
        return await self._get("/api/v1")

    async def get_posture(self) -> JsonObject:
        """Return the current compliance posture (score, frameworks, violations)."""
        return await self._get("/api/v1/posture/current")

    async def posture_as_of(self, as_of: str) -> JsonObject:
        """Return the posture as of a point in time.

        Selects the newest snapshot whose ``evaluated_at`` is at or before
        ``as_of`` (an ISO date or datetime). The result echoes ``found``,
        ``evaluated_at``, ``assessment_hash``, and ``requested_as_of``.
        """
        return await self._get("/api/v1/posture/as-of", params={"as_of": as_of})

    # --- lake-backed read collections --------------------------------------
    async def list_controls(
        self,
        *,
        limit: int | None = None,
        offset: int | None = None,
        sort: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> list[JsonObject]:
        """List control posture rows."""
        return await self._get("/api/v1/controls", params=_params(limit=limit, offset=offset, sort=sort, filter=filter))

    async def list_control_tests(
        self,
        *,
        limit: int | None = None,
        offset: int | None = None,
        sort: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> list[JsonObject]:
        """List control test results."""
        return await self._get(
            "/api/v1/control-tests", params=_params(limit=limit, offset=offset, sort=sort, filter=filter)
        )

    async def list_evidence(
        self,
        *,
        limit: int | None = None,
        offset: int | None = None,
        sort: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> list[JsonObject]:
        """List normalized evidence events."""
        return await self._get("/api/v1/evidence", params=_params(limit=limit, offset=offset, sort=sort, filter=filter))

    async def list_assets(
        self,
        *,
        limit: int | None = None,
        offset: int | None = None,
        sort: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> list[JsonObject]:
        """List assets with their risk scores."""
        return await self._get("/api/v1/assets", params=_params(limit=limit, offset=offset, sort=sort, filter=filter))

    async def list_violations(
        self,
        *,
        limit: int | None = None,
        offset: int | None = None,
        sort: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> list[JsonObject]:
        """List open posture violations."""
        return await self._get(
            "/api/v1/violations", params=_params(limit=limit, offset=offset, sort=sort, filter=filter)
        )

    async def list_snapshots(
        self,
        *,
        limit: int | None = None,
        offset: int | None = None,
        sort: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> list[JsonObject]:
        """List point-in-time assessment snapshots."""
        return await self._get(
            "/api/v1/snapshots", params=_params(limit=limit, offset=offset, sort=sort, filter=filter)
        )

    async def create_snapshot(self, reason: str = "api_request") -> JsonObject:
        """Write a new assessment snapshot to the gold zone and return its record."""
        return await self._post("/api/v1/snapshots", json={"reason": reason})

    # --- risk register (GRC) -----------------------------------------------
    async def list_risks(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        owner: str | None = None,
    ) -> list[JsonObject]:
        """List risk-register entries, optionally filtered by status/severity/owner."""
        return await self._get("/api/v1/risks", params=_params(status=status, severity=severity, owner=owner))

    async def create_risk(self, **fields: Any) -> JsonObject:
        """Create a risk-register entry (e.g. ``title=``, ``severity=``, ``owner=``)."""
        return await self._post("/api/v1/risks", json=dict(fields))

    async def get_risk(self, risk_id: str) -> JsonObject:
        """Fetch a single risk by id.

        The server exposes risks as a tenant-scoped collection; this reads the
        list and selects the matching id, raising :class:`TrustOpsError` (404)
        when absent so the method behaves like a direct GET.
        """
        for risk in await self.list_risks():
            if risk.get("id") == risk_id:
                return risk
        raise TrustOpsError(404, [{"code": "not_found", "detail": "risk not found"}])

    async def update_risk(self, risk_id: str, **fields: Any) -> JsonObject:
        """Patch a risk-register entry; ``fields`` are the columns to change."""
        return await self._patch(f"/api/v1/risks/{risk_id}", json=dict(fields))

    async def delete_risk(self, risk_id: str) -> JsonObject:
        """Delete a risk-register entry."""
        return await self._delete(f"/api/v1/risks/{risk_id}")

    # --- remediation -------------------------------------------------------
    async def list_tasks(
        self,
        *,
        status: str | None = None,
        owner: str | None = None,
        overdue: bool | None = None,
    ) -> list[JsonObject]:
        """List remediation tasks, optionally filtered by status/owner/overdue."""
        return await self._get("/api/v1/remediation/tasks", params=_params(status=status, owner=owner, overdue=overdue))

    async def create_task(self, **fields: Any) -> JsonObject:
        """Create a remediation task (e.g. ``title=``, ``owner=``, ``priority=``)."""
        return await self._post("/api/v1/remediation/tasks", json=dict(fields))
