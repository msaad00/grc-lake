"""Tenant-scoped bounded reads from the shared request audit sink."""

import json

from sqlalchemy import JSON, cast, func, select

from security_lakehouse.db.models import DistributedRequestAudit


def request_rows(factory, cluster_id, tenant_id, *, actor=None, limit=200):
    table = DistributedRequestAudit
    query = select(table.event_json).where(table.cluster_id == cluster_id, table.tenant_id == tenant_id)
    if actor is not None:
        query = query.where(cast(table.event_json, JSON)["actor"].as_string() == actor)
    with factory() as session:
        return [
            json.loads(raw)
            for raw in session.scalars(query.order_by(table.occurred_at.desc(), table.event_id).limit(limit))
        ]


def request_count(factory, cluster_id, tenant_id, *, actor=None) -> int:
    """Total rows :func:`request_rows` would page through with no limit."""
    table = DistributedRequestAudit
    query = select(func.count()).select_from(table).where(table.cluster_id == cluster_id, table.tenant_id == tenant_id)
    if actor is not None:
        query = query.where(cast(table.event_json, JSON)["actor"].as_string() == actor)
    with factory() as session:
        return int(session.scalar(query) or 0)
