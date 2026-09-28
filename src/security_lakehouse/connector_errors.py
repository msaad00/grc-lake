"""Operator-facing connector errors and collection-gap reporting.

Run records cross the HTTP boundary, so third-party exception text is never
persisted verbatim (see ``connector_state._safe_run_error``). Errors raised by
our own connector code are different: their messages are written here, carry
no credentials, and tell an operator what to fix. Raising one of these types is
the contract that the message is safe to surface. Keep messages free of file
paths and URLs; the run-record persistence guard reduces any error containing
``/`` to its class name.
"""

from __future__ import annotations

from typing import Any

COLLECTION_GAP_ATTRIBUTE = "collection_gap"


class ConnectorOperatorError(Exception):
    """A connector error whose message is safe and actionable for operators."""


class ConnectorConfigError(ConnectorOperatorError, ValueError):
    """The connector configuration or local runtime cannot support the request."""


class ConnectorAccessError(ConnectorOperatorError, RuntimeError):
    """The provider refused or could not serve a read the connector needs."""


class CollectionGapError(ConnectorAccessError):
    """One readable-scope sub-collection is unavailable (API disabled, permission missing).

    Collectors catch this per sub-collection, record a coverage-gap evidence row,
    and keep collecting the rest instead of failing the whole sync.
    """

    def __init__(
        self,
        message: str,
        *,
        collection: str,
        reason: str,
        api: str | None = None,
        permission: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.collection = collection
        self.reason = reason
        self.api = api
        self.permission = permission

    def attributes(self) -> dict[str, Any]:
        return {
            COLLECTION_GAP_ATTRIBUTE: True,
            "collection": self.collection,
            "reason": self.reason,
            "api": self.api,
            "permission": self.permission,
            "message": self.message,
        }


def collection_gaps(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Summarize coverage-gap evidence rows for run metadata and CLI output."""
    gaps: list[dict[str, Any]] = []
    for row in rows:
        attributes = row.get("attributes")
        if not isinstance(attributes, dict) or attributes.get(COLLECTION_GAP_ATTRIBUTE) is not True:
            continue
        gaps.append(
            {
                "source": row.get("source"),
                "collection": attributes.get("collection"),
                "reason": attributes.get("reason"),
                "api": attributes.get("api"),
                "permission": attributes.get("permission"),
                "message": attributes.get("message"),
            }
        )
    return gaps


__all__ = [
    "COLLECTION_GAP_ATTRIBUTE",
    "CollectionGapError",
    "ConnectorAccessError",
    "ConnectorConfigError",
    "ConnectorOperatorError",
    "collection_gaps",
]
