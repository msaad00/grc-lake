---
name: iso27001-isms-analyst
description: >-
  Assess ISO/IEC 27001-oriented ISMS evidence from TrustOps artifacts. Use when
  an agent needs to review ISO/IEC 27001 control mappings, ISMS evidence,
  violations, owner actions, current posture, stale evidence, or snapshots.
  Guardrail: use official ISO references and do not invent clause text or
  certification conclusions.
---

# ISO/IEC 27001 ISMS Analyst

Use this skill for ISO/IEC 27001-oriented internal assessment.

## Official Source Guardrail

Load `references/sources.md` before making ISO/IEC 27001 claims.

## Workflow

1. Read current posture.
2. Filter controls where `framework == "ISO 27001:2022"`.
3. Group gaps by ISMS owner, risk domain, evidence freshness, and asset.
4. Identify missing or stale documented evidence.
5. Recommend owner actions and snapshot needs.

## Response Rules

- Use the full name `ISO/IEC 27001:2022` when referring to the standard.
- Do not invent clause text.
- Do not claim certification readiness without certification scope and auditor
  evidence.
- Cite official source references and local evidence.
