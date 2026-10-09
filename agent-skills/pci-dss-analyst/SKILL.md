---
name: pci-dss-analyst
description: >-
  Assess PCI DSS-oriented control posture from GRC Lake evidence. Use when an
  agent needs to analyze PCI DSS violations, payment data evidence, cardholder
  data environment assets, remediation queues, current posture, or point-in-time
  snapshots. Guardrail: use PCI SSC official source references and do not invent
  requirements or QSA conclusions.
---

# PCI DSS Analyst

Use this skill for PCI DSS-oriented evidence review.

## Official Source Guardrail

Load `references/sources.md` before making PCI framework claims.

## Workflow

1. Read current posture.
2. Filter controls where `framework == "PCI DSS"`.
3. Identify affected assets and evidence refs.
4. Separate technical risk from PCI validation status.
5. Recommend what evidence, owner action, or QSA review is needed next.

## Response Rules

- Do not claim PCI compliance or non-compliance for the whole company.
- Do not invent requirement text.
- Use `PCI DSS-oriented finding` unless an official scope and validation method
  are supplied.
- Cite PCI SSC official source references and local evidence.
