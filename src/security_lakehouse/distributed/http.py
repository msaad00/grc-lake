"""ASGI boundary for replica-local reads and atomic distributed mutations."""

from __future__ import annotations

import asyncio
import hashlib
import sys
import tempfile
import uuid

from fastapi import HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from starlette.requests import Request
from starlette.responses import JSONResponse

from security_lakehouse import api_contract
from security_lakehouse.auth.dependencies import get_identity
from security_lakehouse.db.models import DistributedShareIndex
from security_lakehouse.distributed.catalog import Conflict
from security_lakehouse.distributed.context import binding


def _error(detail, status_code, *, retry=False):
    return JSONResponse(
        api_contract.error_envelope(
            "distributed_unavailable" if status_code == 503 else "distributed_rejected", detail
        ),
        status_code=status_code,
        headers={"Retry-After": "1"} if retry else None,
    )


class RejectedResponse(RuntimeError):
    """An error response must not publish partial file or domain database state."""


class DistributedMiddleware:
    def __init__(self, app, *, runtime, factory, read_only=False, audit_sampler=None):
        self.app = app
        self.runtime = runtime
        self.factory = factory
        self.read_only = read_only
        self.audit_sampler = audit_sampler
        from security_lakehouse.runtime_environment import runtime_env

        capacity = int(runtime_env().get("GRC_LAKE_WORKSPACE_CONCURRENCY", "4"))
        if not 1 <= capacity <= 64:
            raise ValueError("workspace concurrency must be between 1 and 64")
        self.slots = asyncio.Semaphore(capacity)

    def _tenant(self, scope):
        request = Request(scope)
        authorization = request.headers.get("authorization", "")
        credentials = None
        if authorization.lower().startswith("bearer "):
            credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=authorization[7:].strip())
        with self.factory() as session:
            if request.url.path.startswith("/api/public/trust/"):
                raw = request.path_params.get("token") or request.url.path.rsplit("/", 1)[-1]
                table = DistributedShareIndex
                return session.scalar(
                    select(table.tenant_id).where(
                        table.cluster_id == self.runtime.catalog.config.cluster_id,
                        table.token_sha256 == hashlib.sha256(raw.encode()).hexdigest(),
                    )
                )
            try:
                return get_identity(request, credentials=credentials, session=session).tenant_id
            except HTTPException:
                # The original route still enforces authorization. Public SSO,
                # invitation and discovery endpoints retain their own contracts.
                return None

    def _audit(self, scope, code, *, independent):
        from security_lakehouse.auth.request_audit import append_request_audit

        details = scope.get("state", {}).get("distributed_audit")
        if details is None:
            identity = scope.get("state", {}).get("identity")
            if identity is None:
                return
            details = {
                "identity": identity,
                "correlation_id": str(uuid.uuid4()),
                "method": scope["method"],
                "route": getattr(scope.get("route"), "path", "/api/{unmatched}"),
                "factory": self.factory,
                "cluster_id": self.runtime.catalog.config.cluster_id,
            }
        token = binding.set(None) if independent else None
        try:
            append_request_audit(
                self.runtime.scratch, **{**details, "status_code": code, "decision": "allow" if code < 400 else "deny"}
            )
        finally:
            if token is not None:
                binding.reset(token)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith("/api/"):
            return await self.app(scope, receive, send)
        if scope["path"] in {"/api/healthz", "/api/v1/healthz", "/api/readyz"}:
            return await self.app(scope, receive, send)
        try:
            tenant = await run_in_threadpool(self._tenant, scope)
        except SQLAlchemyError:
            return await _error("cluster metadata unavailable", 503)(scope, receive, send)
        if (
            self.read_only
            and scope["method"] not in {"GET", "HEAD", "OPTIONS"}
            and not scope["path"].startswith(("/api/auth/", "/api/v1/auth/"))
        ):
            scope.setdefault("state", {})["distributed_audit"] = {
                "method": scope["method"],
                "route": "/api/{read-replica-denied}",
                "identity": scope.get("state", {}).get("identity"),
                "correlation_id": str(uuid.uuid4()),
                "factory": self.factory,
                "cluster_id": self.runtime.catalog.config.cluster_id,
            }
            identity = scope.get("state", {}).get("identity")
            client = scope.get("client") or ("unknown", 0)
            if (
                identity is not None
                or self.audit_sampler is None
                or self.audit_sampler.should_record(f"{client[0]}|deny")
            ):
                await run_in_threadpool(self._audit, scope, 405, independent=True)
            return await _error("read replica cannot accept mutations", 405)(scope, receive, send)
        if tenant is None:
            return await self.app(scope, receive, send)
        if self.slots.locked():
            await run_in_threadpool(self._audit, scope, 503, independent=True)
            return await _error("replica workspace capacity reached", 503, retry=True)(scope, receive, send)
        async with self.slots:
            return await self._dispatch(tenant, scope, receive, send)

    async def _dispatch(self, tenant, scope, receive, send):
        mutation = scope["method"] not in {"GET", "HEAD", "OPTIONS"}
        from security_lakehouse.operation_jobs import supported

        queue_only = scope["path"] == "/api/v1/operations" or scope["path"].startswith("/api/v1/operations/")
        async_admission = (
            scope["method"] == "POST"
            and supported(scope["path"])
            and "respond-async" in Request(scope).headers.get("prefer", "").lower()
        )
        manager = None
        token = None
        response_started = False

        async def forward(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            try:
                if not mutation:
                    manager = (
                        self.runtime.metadata_read(tenant) if queue_only else self.runtime.read_transaction(tenant)
                    )
                    workspace = await run_in_threadpool(manager.__enter__)
                    token = binding.set(workspace)
                    await self.app(scope, receive, forward)
                    active, manager = manager, None
                    await run_in_threadpool(active.__exit__, None, None, None)
                    return
                manager = (
                    self.runtime.metadata_transaction(tenant)
                    if queue_only or async_admission
                    else self.runtime.transaction(tenant)
                )
                workspace = await run_in_threadpool(manager.__enter__)
                token = binding.set(workspace)
                # Do not acknowledge a write until both SQL and the lake pointer
                # commit. Spooled response bodies bound memory and total output.
                start = None
                size = 0
                with tempfile.SpooledTemporaryFile(max_size=1024**2) as body:

                    async def capture(message):
                        nonlocal start, size
                        if message["type"] == "http.response.start":
                            start = message
                        elif message["type"] == "http.response.body":
                            data = message.get("body", b"")
                            size += len(data)
                            if size > 64 * 1024**2:
                                raise ValueError("distributed mutation response exceeds 64 MiB")
                            body.write(data)

                    await self.app(scope, receive, capture)
                    if start is None:
                        raise RuntimeError("application returned no response")
                    if start["status"] < 400:
                        await run_in_threadpool(self._audit, scope, start["status"], independent=False)
                    active, manager = manager, None
                    if start["status"] >= 400:
                        failure = RejectedResponse()
                        await run_in_threadpool(active.__exit__, type(failure), failure, None)
                        await run_in_threadpool(self._audit, scope, start["status"], independent=True)
                    else:
                        await run_in_threadpool(active.__exit__, None, None, None)
                    manager = None
                    await forward(start)
                    body.seek(0)
                    while chunk := body.read(64 * 1024):
                        await send({"type": "http.response.body", "body": chunk, "more_body": True})
                    await send({"type": "http.response.body", "body": b"", "more_body": False})
            finally:
                if manager is not None:
                    import anyio

                    # Roll back on cancellation as well as ordinary exceptions,
                    # while letting cancellation propagate to the ASGI server.
                    with anyio.CancelScope(shield=True):
                        await run_in_threadpool(manager.__exit__, *sys.exc_info())
        except Exception as exc:
            if response_started:
                raise
            code = 409 if isinstance(exc, Conflict) else 503
            await run_in_threadpool(self._audit, scope, code, independent=True)
            await _error("distributed workspace unavailable; inspect operation status before retrying", code)(
                scope, receive, send
            )
        finally:
            if token is not None:
                binding.reset(token)
