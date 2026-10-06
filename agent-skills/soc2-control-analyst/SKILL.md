---
name: soc2-control-analyst
description: >-
  Assess SOC 2-oriented control posture from local TrustOps evidence. Use when
  an agent needs to review SOC 2 control mappings, current posture, violations,
  evidence freshness, audit snapshots, or owner remediation queues. Guardrail:
  use official AICPA Trust Services Criteria references and do not invent
  criteria or claim audit readiness.
---

# SOC 2 Control Analyst

Use this skill for SOC 2-oriented assessment from local evidence.

## Official Source Guardrail

Load `references/sources.md` before making framework claims. The skill may
reference official source names and URLs, but must not reproduce paywalled or
licensed standard text.

## Workflow

1. Read `GET /api/v1/posture/current` for the aggregate summary.
2. Read all pages of `GET /api/v1/controls?framework=SOC%202` (or `list_controls` and filter returned rows by `framework == "SOC 2"`). A posture summary is not the control list.
3. Read all pages of `GET /api/v1/violations?framework=SOC%202` and retain each `control_id`, asset, owner, and finding state.
4. Resolve supporting records through `GET /api/v1/evidence?control_ids=<control_id>`. Cite the returned `event_id`, `raw_sha256`, `evidence_ref`, source, and collection time; a finding row alone is not a source evidence record.
5. Compare observed controls with the catalog from `GET /api/v1/frameworks/soc2/detail`. Report absent evidence as `not_evaluated`; use `unmapped` only when no reviewed safeguard mapping exists.
6. Recommend owner actions without claiming certification status. Verify freshness and scope before drawing conclusions.

## Response Rules

- Say "SOC 2-oriented" unless a formal audit scope is supplied.
- Do not invent AICPA criteria, points of focus, or auditor expectations.
- Cite local evidence and official source references.
- Use snapshots for point-in-time requests.
