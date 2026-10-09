# AI inventory and deployment context

These safeguards are proposed GRC Lake curations of the cited NIST outcomes. They are not NIST-published crosswalks, human-reviewed equivalence, certification, or proof of automated discovery. Existing collector coverage remains unchanged.

## SG-AIINVENTORY-001 — AI system inventory and risk resourcing

Maintain an AI system inventory with resources assigned according to documented risk priorities.

Evidence: Current inventory identifies models, agents, AI services, owners, lifecycle state, scope and risk priority; a resource allocation record shows how inventory and oversight are maintained.

Source: [NIST AI RMF 1.0 (NIST AI 100-1)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf), Table 1, GOVERN 1.6.

## SG-AICONTEXT-001 — AI deployment context and affected users

Document intended and beneficial uses, deployment settings, users, applicable expectations, impacts, assumptions, limitations and relevant evaluation metrics.

Evidence: A reviewed context record links each AI system to intended uses, deployment environments, affected users and communities, applicable laws and norms, beneficial and adverse impacts, assumptions, limitations and TEVV metrics. Missing business or deployment context is recorded as unknown.

Source: [NIST AI RMF 1.0 (NIST AI 100-1)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf), Table 2, MAP 1.1.

## SG-AICATEGORIZATION-001 — AI tasks and implementation methods

Define the AI tasks and methods that support each intended use.

Evidence: A current system record identifies supported tasks and methods, such as generation, classification or recommendation, and the associated models, agent tools and services. An inventory entry alone does not demonstrate task categorization.

Source: [NIST AI RMF 1.0 (NIST AI 100-1)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf), Table 2, MAP 2.1.

## AI life cycle safeguards

Sixteen safeguards cover the AI system life cycle from requirements to retirement. Every mapping is `proposed`: it adds evaluatable coverage and no attestable coverage until a reviewer confirms it. NIST AI RMF members cite the pinned NIST AI 100-1 PDF (Tables 1-4); CSF members cite the pinned CSF 2.0 PDF. ISO/IEC 42001 is licensed and the EU AI Act has no pinned copy in this repository, so those members carry identifiers only. The primary requirement of each safeguard is in bold.

| Safeguard                                                                          | Family                    | NIST AI RMF                                                                 | ISO/IEC 42001 Annex A                    | EU AI Act      | Other                                 | Evidence basis                                      |
| ---------------------------------------------------------------------------------- | ------------------------- | --------------------------------------------------------------------------- | ---------------------------------------- | -------------- | ------------------------------------- | --------------------------------------------------- |
| `SG-AIEVALUATION-001` Pre-deployment AI evaluation (TEVV)                          | AI governance             | **MEASURE-2.1**, MAP-2.3, MEASURE-1.1, MEASURE-2.3, MEASURE-2.5, MANAGE-1.1 | A.6.2.4, A.6.2.5                         | Art.15         | —                                     | Attested                                            |
| `SG-AITRUSTWORTHINESS-001` AI safety, fairness and explainability evaluation       | AI governance             | **MEASURE-2.6**, MEASURE-2.11, MEASURE-2.9, MEASURE-3.2                     | —                                        | —              | —                                     | Attested                                            |
| `SG-AIPERFORMANCEMONITORING-001` Production AI performance and drift monitoring    | Detection                 | **MEASURE-4.2**, MEASURE-4.1, MEASURE-4.3, MANAGE-2.2                       | A.6.2.6                                  | Art.72         | —                                     | `clickhouse-telemetry-lake`, `ticketing` + attested |
| `SG-AIINCIDENT-001` AI incident handling and reporting                             | Incident response         | **MANAGE-2.3**, GOVERN-4.3, MANAGE-4.3                                      | A.8.4                                    | Art.26         | —                                     | `siem-alerts`, `ticketing` + attested               |
| `SG-AIPROVENANCE-001` Third-party model and dataset provenance (AI-BOM)            | Third-party risk          | **MANAGE-3.2**, GOVERN-6.2, GOVERN-6.1                                      | A.4.2, A.4.4, A.10.2, A.10.3             | —              | ISO27001-A.5.21                       | `kubernetes-cluster` + attested                     |
| `SG-AIOVERSIGHT-001` Human oversight of AI systems                                 | AI governance             | **MAP-3.5**, MAP-2.2, MAP-3.4                                               | A.4.6                                    | Art.14, Art.26 | —                                     | `runtime-gateway` + attested                        |
| `SG-AIDATAGOVERNANCE-001` AI training and evaluation data governance               | AI governance             | MEASURE-2.2                                                                 | A.7.2, A.7.3, A.7.4, A.7.5, A.7.6, A.4.3 | **Art.10**     | GDPR-Art.5, GDPR-Art.6                | Attested                                            |
| `SG-AITRANSPARENCY-001` AI transparency and user disclosure                        | AI governance             | MEASURE-2.8                                                                 | A.8.2, A.8.5, A.6.2.7                    | **Art.13**     | —                                     | Attested                                            |
| `SG-AIRUNTIMEACCESS-001` Access control for AI inference endpoints and agent tools | Identity and access       | MEASURE-2.7, MAP-4.2                                                        | A.6.2.8                                  | Art.12, Art.15 | **NIST-CSF-PR.AA-05**, ISO27001-A.8.3 | `runtime-gateway`                                   |
| `SG-AIFEEDBACK-001` AI feedback, appeals and concern reporting                     | AI governance             | **MEASURE-3.3**, GOVERN-5.1, GOVERN-5.2, MAP-5.2                            | A.3.3, A.8.3                             | —              | —                                     | `jira-ticketing`, `ticketing` + attested            |
| `SG-AILIFECYCLECHANGE-001` AI model change, rollback and decommissioning           | Change management         | **GOVERN-1.7**, MANAGE-2.4, MANAGE-4.2                                      | —                                        | —              | ISO27001-A.8.32                       | `ticketing` + attested                              |
| `SG-AIIMPACT-001` AI benefit, cost and impact assessment                           | AI governance             | **MAP-5.1**, MAP-3.1, MAP-3.2, MANAGE-2.1                                   | A.5.2, A.5.3, A.5.4, A.5.5               | —              | —                                     | Attested                                            |
| `SG-AISYSTEMSPEC-001` AI system requirements and design documentation              | Secure development        | **MAP-1.6**, MAP-3.3                                                        | A.6.2.2, A.6.2.3                         | Art.11         | —                                     | Attested                                            |
| `SG-AIRISKTREATMENT-001` AI risk treatment and residual risk                       | Risk management           | **MANAGE-1.3**, MANAGE-1.4                                                  | —                                        | Art.9          | —                                     | `ticketing` + attested                              |
| `SG-AIMEASUREMENTREVIEW-001` Independent review of AI measurement                  | Risk management           | **MEASURE-1.3**, MEASURE-1.2, MEASURE-2.13                                  | —                                        | —              | —                                     | Attested                                            |
| `SG-AICOMPUTE-001` AI compute capacity and environmental footprint                 | Availability and recovery | MEASURE-2.12                                                                | **A.4.5**                                | —              | ISO27001-A.8.6                        | Attested                                            |

Safeguards that operate a general control sit in that control's family: inference and agent-tool access control is in Identity and access, AI incident handling in Incident response, and model and dataset provenance in Third-party risk.

### Evidence wiring

The `runtime-gateway` connector tags every tool-call, policy-decision and runtime-block event with `NIST-AI-RMF-MEASURE-2.7` by default, and `SG-AIRUNTIMEACCESS-001` claims that requirement, so gateway evidence reaches the runtime access safeguard without configuration. The `kubernetes-cluster` connector does not yet identify model-serving workloads; its image provenance evidence covers serving container images only, not model weights, and `SG-AIPROVENANCE-001` says so. The other safeguards name connectors whose records hold their evidence (`siem-alerts`, `ticketing`, `jira-ticketing`, `clickhouse-telemetry-lake`). Those connectors tag general security requirements by default, not AI ones, so today that evidence is attested; `siem-alerts` and `clickhouse-telemetry-lake` rows that list an AI requirement in their `controls` field do reach the safeguard.

### Intentionally unmapped

- NIST AI RMF GOVERN 3.1, GOVERN 4.1 and MAP 1.2 ask for demographically diverse, interdisciplinary teams and a safety-first culture. No operated safeguard produces evidence for them, so they stay unmapped rather than being attached to a safeguard that does not test them.
- ISO/IEC 42001 A.2.3 (alignment with other organizational policies) and A.10.4 (customers) are policy-level obligations without AI-system evidence of their own.
- EU AI Act Article 50 (transparency for certain AI systems) and Article 73 (serious incident reporting) are not in the seeded EU AI Act pack. `SG-AITRANSPARENCY-001` and `SG-AIINCIDENT-001` are written to cover them once the pack adds those articles.

## Evaluation boundary

The executable rule rejects missing or stale evidence and open findings. It does not establish semantic completeness of uploaded documents. A reviewer must check the stated evidence requirement and system scope before promoting a proposed mapping. Agents may submit observations or draft responses; recorded approval remains separate from deterministic evaluation.

Annex A.6.1.3 is distinct from management clause 6.1.3. The restored
`ISO42001-A.6.1.3` requirement remains unmapped pending independent review;
existing risk-treatment mappings do not attest responsible development processes.
