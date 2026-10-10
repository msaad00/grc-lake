"""Bounded request schemas for GRC workflow routers."""

from __future__ import annotations

from pydantic import Field

from security_lakehouse.server_routes.schemas.base import (
    MAX_LIST_ITEMS,
    BoundedObject,
    DocumentStr,
    EmailStr,
    IdStr,
    NameStr,
    TextStr,
    TitleStr,
    TokenStr,
)
from security_lakehouse.server_routes.schemas.base import StrictModel as _StrictModel


class CreateTaskRequest(_StrictModel):
    title: TitleStr
    description: TextStr = ""
    control_id: IdStr | None = None
    violation_id: IdStr | None = None
    owner: NameStr = ""
    priority: TokenStr = "medium"
    due_at: TokenStr | None = None


class UpdateTaskRequest(_StrictModel):
    title: TitleStr | None = None
    description: TextStr | None = None
    owner: NameStr | None = None
    status: TokenStr | None = None
    priority: TokenStr | None = None
    due_at: TokenStr | None = None
    resolution_note: TextStr | None = None


class VerifyTaskRequest(_StrictModel):
    resolution_note: TextStr = ""


class CreateEvidenceRequestRequest(_StrictModel):
    control_id: IdStr
    requested_from: EmailStr = ""
    note: TextStr = ""
    due_at: TokenStr | None = None


class EvidenceRequestStatusRequest(_StrictModel):
    status: TokenStr


class CreateExceptionRequest(_StrictModel):
    control_id: IdStr
    reason: TextStr = ""
    expires_at: TokenStr | None = None


class CreateRiskRequest(_StrictModel):
    title: TitleStr
    description: TextStr = ""
    category: NameStr = ""
    severity: TokenStr = "medium"
    likelihood: TokenStr = "medium"
    impact: TokenStr = "medium"
    status: TokenStr = "open"
    treatment: TextStr = ""
    owner: NameStr = ""
    control_id: IdStr | None = None
    asset_id: IdStr | None = None
    due_at: TokenStr | None = None


class UpdateRiskRequest(_StrictModel):
    title: TitleStr | None = None
    description: TextStr | None = None
    category: NameStr | None = None
    severity: TokenStr | None = None
    likelihood: TokenStr | None = None
    impact: TokenStr | None = None
    status: TokenStr | None = None
    treatment: TextStr | None = None
    owner: NameStr | None = None
    control_id: IdStr | None = None
    asset_id: IdStr | None = None
    due_at: TokenStr | None = None


class CreateWebhookRequest(_StrictModel):
    url: str = Field(min_length=1, max_length=2048)
    event_types: list[TokenStr] = Field(min_length=1, max_length=MAX_LIST_ITEMS)
    secret: str | None = Field(default=None, min_length=16, max_length=255)
    description: str = Field(default="", max_length=255)
    enabled: bool = True


class UpdateWebhookRequest(_StrictModel):
    url: str | None = Field(default=None, min_length=1, max_length=2048)
    event_types: list[TokenStr] | None = Field(default=None, min_length=1, max_length=MAX_LIST_ITEMS)
    secret: str | None = Field(default=None, min_length=16, max_length=255)
    description: str | None = Field(default=None, max_length=255)
    enabled: bool | None = None


class AdoptPolicyTemplateRequest(_StrictModel):
    template_id: IdStr
    variables: BoundedObject = {}
    owner: NameStr = ""


class UpdatePolicyDocumentRequest(_StrictModel):
    title: TitleStr | None = None
    content: DocumentStr | None = None
    owner: NameStr | None = None
    variables: BoundedObject | None = None
    status: TokenStr | None = None


class RecordPolicyAcknowledgmentRequest(_StrictModel):
    user_email: EmailStr | None = None
    display_name: NameStr = ""


class CreateCampaignRequest(_StrictModel):
    name: NameStr
    description: TextStr = ""
    scope: TokenStr = "all"
    control_id: IdStr | None = None
    due_at: TokenStr | None = None


class CampaignStatusRequest(_StrictModel):
    status: TokenStr


class CreateVendorAssessmentRequest(_StrictModel):
    vendor_name: NameStr
    template_id: IdStr
    owner: NameStr = ""
    control_id: IdStr | None = None
    due_at: TokenStr | None = None


class UpdateVendorAssessmentRequest(_StrictModel):
    vendor_name: NameStr | None = None
    owner: NameStr | None = None
    control_id: IdStr | None = None
    due_at: TokenStr | None = None
    responses: BoundedObject | None = None
    status: TokenStr | None = None


class AddReviewItemRequest(_StrictModel):
    subject_id: IdStr
    subject_name: NameStr = ""
    source: NameStr = ""
    access_summary: TextStr = ""


class ReviewDecisionRequest(_StrictModel):
    decision: TokenStr
    note: TextStr = ""


class CreateTagRequest(_StrictModel):
    name: NameStr
    color: TokenStr = ""


class AttachTagRequest(_StrictModel):
    tag_id: IdStr
    entity_type: TokenStr
    entity_id: IdStr


class CreateSavedViewRequest(_StrictModel):
    surface: TokenStr
    name: NameStr
    filters: BoundedObject = {}
