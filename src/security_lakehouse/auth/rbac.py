"""Role-based access control: the role -> scope map and request identity."""

from __future__ import annotations

from dataclasses import dataclass

ROLE_SCOPES: dict[str, frozenset[str]] = {
    "admin": frozenset(
        {
            "read",
            "write",
            "snapshot",
            "auth_admin",
            "connector_manage",
            "workflow_manage",
            "control_manage",
            "evidence_request",
            "mapping_review",
            "workpaper_review",
        }
    ),
    "security_admin": frozenset(
        {"read", "write", "snapshot", "connector_manage", "workflow_manage", "control_manage", "evidence_request"}
    ),
    # Confirms or rejects safeguard->requirement mappings for the organization
    # (see security_lakehouse.mapping_review) and reviews immutable audit workpapers.
    "compliance_reviewer": frozenset({"read", "mapping_review", "workpaper_review"}),
    "contributor": frozenset({"read", "write", "workflow_run", "evidence_request"}),
    "auditor": frozenset({"read"}),
    "read_only": frozenset({"read"}),
}


def scopes_for_role(role: str) -> frozenset[str]:
    """Scopes granted to a role; unknown roles get nothing."""
    return ROLE_SCOPES.get(role, frozenset())


@dataclass(frozen=True)
class Identity:
    """The authenticated principal resolved for a request."""

    user_id: str
    tenant_id: str
    email: str
    role: str
    scopes: frozenset[str]
    workspace_id: str | None = None
    api_key_id: str | None = None
    # Set when a commercial workspace's subscription has lapsed: scopes are
    # narrowed to reads until billing is fixed.
    billing_read_only: bool = False
    # How the principal authenticated: ``api_key`` (bearer: agents, CI, MCP,
    # scripts), ``session:<idp>`` (a signed-in console session), or
    # ``insecure`` (local no-auth mode). Unknown means fail closed.
    auth_method: str = "unknown"

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes

    @property
    def is_interactive_session(self) -> bool:
        """True for a signed-in console session (or local no-auth mode), never a bearer key."""
        return self.auth_method.startswith("session:") or self.auth_method == "insecure"
