"""Application-state ORM models (server mode).

The first slice is the multi-tenancy spine — ``Tenant`` and ``User`` — that
authentication and RBAC build on. Identifiers are string UUIDs so the schema
is portable across SQLite (default single-node) and Postgres (production)
without database-specific column types.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from security_lakehouse.db.base import Base

# Server-mode roles. ``viewer`` and ``analyst`` are not accepted aliases here;
# the API surface uses explicit product roles so audit events are unambiguous.
USER_ROLES = ("admin", "security_admin", "compliance_reviewer", "contributor", "auditor", "read_only")

# Remediation workflow vocabularies.
REMEDIATION_STATUSES = ("open", "in_progress", "blocked", "resolved", "dismissed")
REMEDIATION_CLOSED = {"resolved", "dismissed"}
REMEDIATION_PRIORITIES = ("low", "medium", "high", "critical")
EVIDENCE_REQUEST_STATUSES = ("open", "fulfilled", "cancelled")
EXCEPTION_STATUSES = ("pending", "active", "revoked", "expired")

# GRC risk-register vocabularies.
RISK_STATUSES = ("open", "mitigating", "accepted", "closed")
RISK_LEVELS = ("low", "medium", "high", "critical")

# Gov POA&M (Plan of Action & Milestones) for CMMC / FedRAMP-style programs.
POAM_STATUSES = ("open", "in_progress", "completed", "risk_accepted")

# Access-review vocabularies (GRC pillar): periodic user-access certification.
# A campaign walks draft → active → completed; each item (one subject's access)
# is certified, revoked, or flagged by a reviewer.
ACCESS_REVIEW_STATUSES = ("draft", "active", "completed", "cancelled")
ACCESS_REVIEW_CLOSED = {"completed", "cancelled"}
ACCESS_REVIEW_DECISIONS = ("pending", "certified", "revoked", "flagged")

# Human/headless agent harness run records.
AGENT_RUN_HARNESSES = ("posture_review", "soc_triage")
AGENT_RUN_STATUSES = ("completed", "failed")

# Commercial hosted workspace invites.
INVITE_STATUSES = ("pending", "accepted", "revoked", "expired")


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _as_aware(value: datetime) -> datetime:
    """Coerce a stored datetime to aware UTC (SQLite drops tzinfo; Postgres keeps it)."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class Tenant(Base):
    """An isolated workspace; all application-state rows hang off a tenant."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    plan_tier: Mapped[str] = mapped_column(String(32), nullable=False, default="starter", server_default="starter")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )

    users: Mapped[list[User]] = relationship(back_populates="tenant", cascade="all, delete-orphan")


class User(Base):
    """A member of a tenant. Email is unique within (not across) a tenant."""

    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="read_only")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    # SCIM: the IdP's identifier for this user, and a soft-delete marker. A SCIM
    # DELETE hides the user from SCIM but keeps the row for the audit trail.
    scim_external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scim_deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="users")
    api_keys: Mapped[list[ApiKey]] = relationship(back_populates="user", cascade="all, delete-orphan")
    sessions: Mapped[list[UserSession]] = relationship(back_populates="user", cascade="all, delete-orphan")


class TenantInvite(Base):
    """Email invite to join a tenant (commercial hosted)."""

    __tablename__ = "tenant_invites"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", "status", name="uq_tenant_invites_pending_email"),
        Index("ix_tenant_invites_token_hash", "token_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="contributor")
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    invited_by: Mapped[str] = mapped_column(String(320), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)


class ScimToken(Base):
    """A per-tenant SCIM bearer token. Only the SHA-256 hash is stored."""

    __tablename__ = "scim_tokens"
    __table_args__ = (Index("ix_scim_tokens_token_hash", "token_hash", unique=True),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    token_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ScimGroup(Base):
    """An IdP group pushed over SCIM; membership drives TrustOps roles via a role map."""

    __tablename__ = "scim_groups"
    __table_args__ = (UniqueConstraint("tenant_id", "display_name", name="uq_scim_groups_tenant_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


class ScimGroupMember(Base):
    """Membership of a user in a SCIM group (both within one tenant)."""

    __tablename__ = "scim_group_members"

    group_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scim_groups.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)


class TenantBilling(Base):
    """Stripe billing state for a tenant (commercial hosted). Stripe is the source of truth."""

    __tablename__ = "tenant_billing"

    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    stripe_customer_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    subscription_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    price_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    past_due_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


class StripeEvent(Base):
    """A processed Stripe webhook event id, so redeliveries are applied once."""

    __tablename__ = "stripe_events"

    event_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


class ApiKey(Base):
    """A bearer credential that acts as a specific user (and inherits its role).

    Only the SHA-256 hash of the token is stored; the plaintext is shown once at
    creation. ``prefix`` is a non-secret display handle (e.g. ``tops_ab12cd34``).
    """

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    prefix: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="api_keys")

    def is_active(self, *, now: datetime | None = None) -> bool:
        """A key is usable when it is neither revoked nor past its expiry."""
        moment = now or _utcnow()
        if self.revoked_at is not None or self.status != "active":
            return False
        return self.expires_at is None or _as_aware(self.expires_at) > moment


class UserSession(Base):
    """A browser session minted after SSO login.

    Only the SHA-256 hash of the session token is stored; the opaque token is
    delivered to the browser in an httpOnly cookie. ``idp`` records which
    identity provider authenticated the session (e.g. ``oidc``).
    """

    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    idp: Mapped[str] = mapped_column(String(32), nullable=False, default="oidc")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="sessions")

    def is_active(self, *, now: datetime | None = None) -> bool:
        """A session is usable when it is neither revoked nor past its expiry."""
        moment = now or _utcnow()
        if self.revoked_at is not None:
            return False
        return _as_aware(self.expires_at) > moment


class RemediationTask(Base):
    """An owned unit of remediation work tied to a control or violation, with an SLA due date."""

    __tablename__ = "remediation_tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    control_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    violation_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    owner: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_note: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    verification_history: Mapped[str] = mapped_column(Text, nullable=False, default="[]", server_default="[]")

    @property
    def is_open(self) -> bool:
        return self.status not in REMEDIATION_CLOSED

    def is_overdue(self, *, now: datetime | None = None) -> bool:
        """Open and past its SLA due date."""
        if self.due_at is None or not self.is_open:
            return False
        return _as_aware(self.due_at) < (now or _utcnow())


class PoamItem(Base):
    """Plan of Action & Milestones row for a gov/defense security requirement."""

    __tablename__ = "poam_items"
    __table_args__ = (Index("ix_poam_items_tenant_framework_status", "tenant_id", "framework_id", "status"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    framework_id: Mapped[str] = mapped_column(String(64), nullable=False, default="cmmc-2-level2")
    requirement_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    control_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    weakness: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    owner: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    milestone: Mapped[str] = mapped_column(Text, nullable=False, default="")
    sprs_points: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    poam_eligible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    remediation_task_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Risk(Base):
    """A GRC risk-register entry: an identified risk with treatment and owner.

    The risk register is a load-bearing GRC pillar — risks are scored
    (severity/likelihood/impact), assigned a treatment and owner, and optionally
    linked to a mitigating control or affected asset. Status walks the
    open → mitigating → accepted/closed lifecycle.
    """

    __tablename__ = "risks"
    __table_args__ = (Index("ix_risks_tenant_status", "tenant_id", "status"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    category: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    likelihood: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    impact: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    treatment: Mapped[str] = mapped_column(Text, nullable=False, default="")
    owner: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    control_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    asset_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


class EvidenceRequest(Base):
    """A request for fresh evidence from a control owner or team."""

    __tablename__ = "evidence_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    control_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    requested_from: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    fulfilled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ControlException(Base):
    """A time-boxed risk acceptance; it never changes an evidence result."""

    __tablename__ = "control_exceptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    control_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    approved_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    requested_by_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    approved_by_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def is_active(self, *, now: datetime | None = None) -> bool:
        """Active and not past its expiry."""
        if self.status != "active" or self.revoked_at is not None:
            return False
        return bool(
            self.requested_by_id
            and self.approved_by_id
            and self.approved_at
            and self.requested_by_id != self.approved_by_id
            and self.expires_at
            and _as_aware(self.expires_at) > (now or _utcnow())
        )


# ---------------------------------------------------------------------------
# Tags + saved views (cross-entity labelling and filter persistence)
# ---------------------------------------------------------------------------


class Tag(Base):
    """A tenant-scoped label that can be attached to any entity type."""

    __tablename__ = "tags"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_tags_tenant_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    color: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


class EntityTag(Base):
    """A many-to-many join between a tag and any entity (control, violation, task...)."""

    __tablename__ = "entity_tags"
    __table_args__ = (UniqueConstraint("tag_id", "entity_type", "entity_id", name="uq_entity_tags_tag_entity"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tag_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tags.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


class SavedView(Base):
    """A named, persisted filter set for a UI surface."""

    __tablename__ = "saved_views"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    surface: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    filters: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


class PostureMetricPoint(Base):
    """A time-series snapshot of tenant posture captured at a point in time.

    Rows are append-only; derived aggregates (MTTR, SLA attainment) are
    computed at read time from ``remediation_tasks`` rather than stored here.
    """

    __tablename__ = "posture_metric_points"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, index=True)
    posture_score: Mapped[float] = mapped_column(nullable=False, default=0.0)
    control_pass_rate: Mapped[float] = mapped_column(nullable=False, default=0.0)
    open_violations: Mapped[int] = mapped_column(nullable=False, default=0)
    critical_violations: Mapped[int] = mapped_column(nullable=False, default=0)
    stale_controls: Mapped[int] = mapped_column(nullable=False, default=0)
    evidence_fresh_pct: Mapped[float] = mapped_column(nullable=False, default=0.0)
    remediation_open: Mapped[int] = mapped_column(nullable=False, default=0)
    remediation_overdue: Mapped[int] = mapped_column(nullable=False, default=0)


class AgentRun(Base):
    """A durable human/headless harness run.

    The harness is intentionally operational state, not compliance truth. It
    records the redacted inputs, proposed actions, deterministic evaluation,
    and any non-fatal model errors so humans, schedulers, MCP tools, and the UI
    can inspect the same run contract.
    """

    __tablename__ = "agent_runs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_agent_runs_tenant_idempotency_key"),
        Index("ix_agent_runs_tenant_harness_created", "tenant_id", "harness", "created_at"),
        Index("ix_agent_runs_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    harness: Mapped[str] = mapped_column(String(64), nullable=False)
    objective: Mapped[str] = mapped_column(Text, nullable=False, default="")
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="rules_only")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    budget_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    evaluation_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    decisions_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    state_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    errors_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AccessReviewCampaign(Base):
    """A periodic user-access certification campaign (GRC access-review pillar).

    A campaign scopes a set of subjects (users/identities, typically sourced from
    a connector's identity evidence) and asks reviewers to certify, revoke, or
    flag each one's access. The campaign + its decisions are the audit evidence
    that access was reviewed — the artifact an auditor asks for under access-
    control criteria (SOC 2 CC6.x, ISO 27001 A.5.18).
    """

    __tablename__ = "access_review_campaigns"
    __table_args__ = (Index("ix_access_review_campaigns_tenant_status", "tenant_id", "status"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    scope: Mapped[str] = mapped_column(String(128), nullable=False, default="all")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")
    control_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    items: Mapped[list[AccessReviewItem]] = relationship(back_populates="campaign", cascade="all, delete-orphan")


class AccessReviewItem(Base):
    """One subject's access under review within a campaign.

    Each item is a single reviewer decision: certify (access is appropriate),
    revoke (should be removed), or flag (needs follow-up). ``subject_id`` is the
    reviewed identity/asset (e.g. ``okta:user:123``); ``access_summary`` is the
    redacted description of what that subject can do.
    """

    __tablename__ = "access_review_items"
    __table_args__ = (Index("ix_access_review_items_campaign_decision", "campaign_id", "decision"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    campaign_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("access_review_campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    subject_id: Mapped[str] = mapped_column(String(255), nullable=False)
    subject_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    access_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    decision: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    reviewer: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )

    campaign: Mapped[AccessReviewCampaign] = relationship(back_populates="items")


POLICY_DOCUMENT_STATUSES = frozenset({"draft", "published", "archived"})


class PolicyDocument(Base):
    """A tenant policy document adopted from a bundled template (GRC policy pillar)."""

    __tablename__ = "policy_documents"
    __table_args__ = (Index("ix_policy_documents_tenant_status", "tenant_id", "status"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    template_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    variables_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    related_control_ids_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    owner: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    review_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PolicyAcknowledgment(Base):
    """Employee acknowledgment of a published tenant policy (GRC attestation pillar)."""

    __tablename__ = "policy_acknowledgments"
    __table_args__ = (
        Index("ix_policy_ack_tenant_policy", "tenant_id", "policy_document_id"),
        UniqueConstraint(
            "tenant_id",
            "policy_document_id",
            "user_email",
            name="uq_policy_ack_tenant_document_email",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    policy_document_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("policy_documents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_email: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    acknowledged_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


VENDOR_ASSESSMENT_STATUSES = frozenset({"draft", "in_review", "completed", "rejected"})


class VendorAssessment(Base):
    """A third-party vendor diligence questionnaire instance (GRC vendor-risk pillar)."""

    __tablename__ = "vendor_assessments"
    __table_args__ = (Index("ix_vendor_assessments_tenant_status", "tenant_id", "status"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vendor_name: Mapped[str] = mapped_column(String(255), nullable=False)
    template_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")
    control_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    owner: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    responses_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ---------------------------------------------------------------------------
# Outbound event webhooks
# ---------------------------------------------------------------------------

# The API is otherwise pull-only; a registered subscription lets a tenant push
# a notification to its own SIEM/ticketing system when something happens,
# instead of polling. Event types are intentionally small and map to concrete,
# detectable state in the assessment engine — see assessment.py's snapshot
# chain diffing for how ``finding.created``/``control.failed`` are derived.
WEBHOOK_EVENT_TYPES = ("finding.created", "assessment.completed", "control.failed")
WEBHOOK_DELIVERY_STATUSES = ("success", "failed")


class WebhookSubscription(Base):
    """A tenant-registered outbound webhook endpoint.

    ``secret`` is stored so every delivery can be HMAC-signed; unlike an
    ``ApiKey`` (a bearer credential we only ever need to compare by hash), a
    webhook secret must be recoverable to sign each outbound request, so it is
    persisted in the application database rather than hashed. It is returned to
    the caller in full only once, at creation.
    """

    __tablename__ = "webhook_subscriptions"
    __table_args__ = (Index("ix_webhook_subscriptions_tenant_enabled", "tenant_id", "enabled"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    secret: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    event_types_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
    last_delivery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_delivery_status: Mapped[str | None] = mapped_column(String(16), nullable=True)


class WebhookDelivery(Base):
    """An audit record of one webhook delivery attempt (final outcome only).

    Deliveries are logged for operator visibility (an auditor asking "did the
    SIEM actually get notified" needs an answer), not replayed from a queue —
    delivery itself is synchronous-with-retry at call time (see
    ``services.webhooks``).
    """

    __tablename__ = "webhook_deliveries"
    __table_args__ = (Index("ix_webhook_deliveries_tenant_subscription", "tenant_id", "subscription_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    subscription_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("webhook_subscriptions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


class SamlAssertionReplay(Base):
    """A consumed SAML assertion ID, kept until its ``NotOnOrAfter`` passes.

    Every replica reads and writes this table, so a captured response replayed
    against a different replica is still rejected. SAML requires assertion IDs
    to be unique per issuer, so the constraint is on (issuer, assertion_id).
    """

    __tablename__ = "saml_assertion_replays"
    __table_args__ = (
        UniqueConstraint("issuer", "assertion_id", name="uq_saml_assertion_replays_issuer_assertion"),
        Index("ix_saml_assertion_replays_expires_at", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    assertion_id: Mapped[str] = mapped_column(String(512), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


class AuditWorkpaper(Base):
    """Immutable evidence snapshot with one attributable independent review."""

    __tablename__ = "audit_workpapers"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    content_json: Mapped[str] = mapped_column(Text, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by_id: Mapped[str] = mapped_column(String(36), nullable=False)
    created_by: Mapped[str] = mapped_column(String(320), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, server_default=func.now())
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="draft", server_default="draft")
    reviewed_by_id: Mapped[str | None] = mapped_column(String(36))
    reviewed_by: Mapped[str | None] = mapped_column(String(320))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_rationale: Mapped[str | None] = mapped_column(Text)
