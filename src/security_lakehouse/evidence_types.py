"""Evidence type normalization for provider-specific connector events."""

from __future__ import annotations

PROVIDER_EVENT_ALIASES: dict[str, tuple[str, ...]] = {
    "aws.iam.user_access": ("cloud.config", "identity.access_review"),
    "aws.iam.mfa_enrollment": ("cloud.config", "identity.access_review"),
    "aws.iam.password_policy": ("cloud.config", "identity.access_review"),
    "azure.cloud.policy_assignment": ("cloud.config", "identity.access_review"),
    "azure.cloud.resource": ("cloud.config",),
    "azure.cloud.role_assignment": ("cloud.config", "identity.access_review"),
    "gcp.cloud.asset": ("cloud.config",),
    "gcp.cloud.iam_binding": ("cloud.config", "identity.access_review"),
    "gcp.cloud.org_policy": ("cloud.config", "identity.access_review"),
    "google_workspace.identity.group_membership": ("identity.access_review",),
    "google_workspace.identity.mfa_enrollment": ("identity.access_review",),
    "google_workspace.identity.user_access": ("identity.access_review",),
    "jira.workflow.ticket": ("remediation.ticket",),
    "jira.workflow.transition": ("remediation.ticket",),
    "okta.identity.mfa_enrollment": ("identity.access_review",),
    "okta.identity.mfa_policy": ("identity.access_review",),
    "okta.identity.user_access": ("identity.access_review",),
    "snowflake.audit.event": ("audit.chain",),
    "snowflake.control.posture": ("cloud.config", "compliance.evidence_bundle"),
    "snowflake.evidence.bundle": ("compliance.evidence_bundle",),
}


def expand_evidence_types(event_type: str) -> list[str]:
    """Return the raw provider event type plus generic GRC Lake aliases."""
    normalized = str(event_type or "").strip()
    if not normalized:
        return []
    return sorted({normalized, *PROVIDER_EVENT_ALIASES.get(normalized, ())})
