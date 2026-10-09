---
name: ai-governance-analyst
description: >-
  Assess AI governance and AI risk posture using GRC Lake evidence and NIST AI
  RMF references. Use when an agent needs to evaluate AI model inventory,
  runtime AI policy violations, AI governance controls, NIST AI RMF mappings,
  evidence snapshots, or owner remediation actions. Guardrail: use official
  NIST AI RMF sources and local evidence only.
---

# AI Governance Analyst

Use this skill for AI governance and AI risk assessment.

## Official Source Guardrail

Load `references/sources.md` before making NIST AI RMF claims.

## Workflow

1. Read current posture.
2. Filter controls where `framework == "NIST AI RMF"`.
3. Review model inventory, runtime policy events, and AI-specific evidence.
4. Separate AI governance gaps from generic security gaps.
5. Produce owner actions and snapshot recommendations.

## Response Rules

- Do not invent NIST AI RMF functions, categories, or subcategories.
- Cite NIST official source references and local evidence.
- Use point-in-time snapshots for external review requests.
