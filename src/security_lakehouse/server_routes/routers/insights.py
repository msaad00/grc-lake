"""Insights routes, registered before generic dispatch."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from security_lakehouse import api_v1
from security_lakehouse.auth.dependencies import get_session, require_scope
from security_lakehouse.auth.rbac import Identity
from security_lakehouse.db import metrics as metrics_db
from security_lakehouse.server_routes.payloads import _params, _redact_payload

_require_read = require_scope("read")
_require_write = require_scope("write")


def build_insights_router(*, lake_for: Callable[[Identity], Path]) -> APIRouter:
    """Bind this workflow to the current request tenant lake."""
    router = APIRouter()

    @router.get("/api/v1/insights/timeseries")
    def insights_timeseries(
        request: Request,
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        raw_limit = api_v1.first_param(_params(request), "limit")
        limit = int(raw_limit) if raw_limit and raw_limit.isdigit() else 90
        limit = min(max(limit, 1), 1000)
        points = metrics_db.list_metric_points(session, tenant_id=identity.tenant_id, limit=limit)
        rows = [metrics_db.metric_point_to_dict(p) for p in points]
        return JSONResponse(
            api_v1.envelope("insights.timeseries", _redact_payload(rows, identity), meta={"count": len(rows)})
        )

    @router.get("/api/v1/insights/remediation")
    def insights_remediation(
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        data = metrics_db.remediation_insights(session, tenant_id=identity.tenant_id)
        return JSONResponse(api_v1.envelope("insights.remediation", _redact_payload(data, identity)))

    @router.get("/api/v1/insights/framework-trends")
    def insights_framework_trends(
        request: Request,
        identity: Identity = Depends(_require_read),
    ) -> JSONResponse:
        raw_limit = api_v1.first_param(_params(request), "limit")
        limit = int(raw_limit) if raw_limit and raw_limit.isdigit() else 90
        limit = min(max(limit, 1), 1000)
        data = metrics_db.framework_readiness_trends(lake_for(identity), limit=limit)
        return JSONResponse(
            api_v1.envelope(
                "insights.framework_trends",
                _redact_payload(data, identity),
                meta={
                    "framework_count": len(data.get("frameworks") or []),
                    "point_count": len(data.get("points") or []),
                },
            )
        )

    @router.get("/api/v1/insights/sla-heatmap")
    def insights_sla_heatmap(
        identity: Identity = Depends(_require_read),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        data = metrics_db.sla_heatmap(session, tenant_id=identity.tenant_id)
        return JSONResponse(api_v1.envelope("insights.sla_heatmap", _redact_payload(data, identity)))

    @router.post("/api/v1/insights/capture", status_code=status.HTTP_201_CREATED)
    def insights_capture(
        identity: Identity = Depends(_require_write),
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        point = metrics_db.capture_metric_point(session, tenant_id=identity.tenant_id, lake_dir=lake_for(identity))
        session.commit()
        return JSONResponse(
            api_v1.envelope("insights.timeseries", metrics_db.metric_point_to_dict(point)),
            status_code=status.HTTP_201_CREATED,
        )

    return router
