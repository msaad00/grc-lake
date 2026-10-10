"""Shared Pydantic bases and field bounds for server request bodies."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    """Reject unknown fields so misnamed agent payloads fail with 422."""

    model_config = ConfigDict(extra="forbid")


# One set of request-field bounds. A field without one lets a single request
# store megabytes per row and replay them into every listing, export, and
# audit-log read.
MAX_ID_CHARS = 200
MAX_NAME_CHARS = 200
MAX_TITLE_CHARS = 500
MAX_TEXT_CHARS = 20_000
MAX_DOCUMENT_CHARS = 200_000
MAX_TOKEN_CHARS = 64
MAX_EMAIL_CHARS = 320
MAX_SECRET_CHARS = 512
MAX_LIST_ITEMS = 100
MAX_OBJECT_KEYS = 200

IdStr = Annotated[str, Field(max_length=MAX_ID_CHARS)]
NameStr = Annotated[str, Field(max_length=MAX_NAME_CHARS)]
TitleStr = Annotated[str, Field(max_length=MAX_TITLE_CHARS)]
TextStr = Annotated[str, Field(max_length=MAX_TEXT_CHARS)]
DocumentStr = Annotated[str, Field(max_length=MAX_DOCUMENT_CHARS)]
TokenStr = Annotated[str, Field(max_length=MAX_TOKEN_CHARS)]
EmailStr = Annotated[str, Field(max_length=MAX_EMAIL_CHARS)]
SecretStr = Annotated[str, Field(max_length=MAX_SECRET_CHARS)]
BoundedObject = Annotated[dict[str, Any], Field(max_length=MAX_OBJECT_KEYS)]
