"""Shared pack control spec type for full and limited framework packs."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PackControlSpec:
    control_id: str
    framework_id: str
    framework: str
    framework_ref: str
    article_id: str
    title: str
    risk_domain: str
    owner: str
    evaluation_rule: str
    evidence_requirement: str
    asset_types: tuple[str, ...]
    source_url: str
    official_source_ref: str
    # NIST SP 800-53 baseline membership (low/moderate/high/privacy); empty for
    # frameworks without baselines.
    baselines: tuple[str, ...] = ()
    # Evidence types a control test expects; empty when a program config owns them.
    required_evidence_types: tuple[str, ...] = ()
    # Date a row was reconciled with its pinned official source; such rows stay
    # proposed until a human reviews them.
    reconciled_at: str | None = None
