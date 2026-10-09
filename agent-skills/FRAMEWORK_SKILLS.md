# Framework Analyst Skills

These skills are the agent interface for the assessment product. They do not
replace auditors, QSAs, or official standards. They guide agents to use local
evidence, current posture, official source references, and bounded conclusions.

| Skill                         | Purpose                                                                        |
| ----------------------------- | ------------------------------------------------------------------------------ |
| `security-operations-analyst` | triage violations, runtime events, SIEM signals, and owner queues              |
| `soc2-control-analyst`        | assess SOC 2-oriented control posture from local mappings and evidence         |
| `pci-dss-analyst`             | assess PCI DSS-oriented evidence and violations with PCI SSC source guardrails |
| `iso27001-isms-analyst`       | assess ISO/IEC 27001 ISMS evidence and control gaps with ISO source guardrails |
| `ai-governance-analyst`       | assess AI governance posture using NIST AI RMF evidence mappings               |

The broader [GRC Lake operator](grc-lake-operator/SKILL.md) skill covers collection,
normalization, evaluation, triage and export.
[Compliance analytics](compliance-analytics/SKILL.md) covers local evidence analysis.

## Guardrails

- Use local posture/evidence first.
- Cite official framework sources when making framework claims.
- Do not invent requirement text or control IDs.
- Mark unsupported controls as `not_mapped`.
- Mark stale or missing evidence as a finding, not as a pass.
- Do not claim certification readiness unless the official assessment scope and
  auditor/QSA validation are available.
