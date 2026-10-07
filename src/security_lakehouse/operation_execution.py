"""Execute persisted operations without constructing the HTTP application.

HTTP and spawned workers share this service. Each child opens and disposes its
own database engine; schema migration remains a server startup responsibility.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy.orm import sessionmaker

from security_lakehouse import api_v1, tenancy
from security_lakehouse.auth.authority import AuthorityError, CredentialReference, resolve_authority
from security_lakehouse.auth.server_mode import assert_insecure_allowed, insecure_requested
from security_lakehouse.db import repository
from security_lakehouse.db.base import create_engine_for, session_factory
from security_lakehouse.db.models import OperationJob
from security_lakehouse.execution_mode import server_execution
from security_lakehouse.services.snapshot_events import snapshot_written_hook


def execute_operation(
    root: Path, row: OperationJob, *, factory: sessionmaker, require_auth: bool
) -> tuple[int, dict[str, Any]]:
    with factory() as session:
        try:
            identity = resolve_authority(
                session,
                CredentialReference(row.user_id, row.tenant_id, row.auth_method, row.api_key_id, row.session_id),
                allow_insecure=not require_auth,
            )
        except AuthorityError:
            return 403, api_v1.error_envelope("forbidden", "operation authority is no longer active")
        if identity.tenant_id != row.tenant_id or not identity.has_scope(api_v1.required_post_scope(row.path)):
            return 403, api_v1.error_envelope("forbidden", "operation authority is no longer active")
        tenant_ids = repository.list_tenant_ids(session) if require_auth else []
        bound = tenancy.resolve_bound_tenant(root, require_auth=require_auth, tenant_ids=tenant_ids)
        lake = tenancy.tenant_lake(root, identity.tenant_id, bound_tenant=bound)
        with server_execution(identity.tenant_id):
            code, payload = api_v1.handle_post(
                row.path,
                json.loads(row.payload_json),
                lake,
                on_snapshot_written=snapshot_written_hook(session, identity.tenant_id),
            )
        session.commit()
        return int(code), payload


def execute_stored_operation(root: Path, row: OperationJob, *, require_auth: bool) -> tuple[int, dict[str, Any]]:
    """Rebuild database access and current authority in an isolated child."""
    assert_insecure_allowed(require_auth=require_auth)
    require_auth = require_auth and not insecure_requested()
    engine = create_engine_for(root)
    try:
        return execute_operation(root, row, factory=session_factory(engine), require_auth=require_auth)
    finally:
        engine.dispose()
