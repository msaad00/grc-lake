# TrustOps documentation

Every guide in `docs/`, grouped by task. New here? Start with the
[5-minute tutorial](TUTORIAL_5_MIN.md) and [architecture](ARCHITECTURE.md).

## Start

| Guide                                                     | Covers                                                             |
| --------------------------------------------------------- | ------------------------------------------------------------------ |
| [5-minute tutorial](TUTORIAL_5_MIN.md)                    | Sample data to evaluated controls, a mapping review, and an export |
| [Product walkthrough](PRODUCT_WALKTHROUGH.md)             | Running the demo and what each console page does                   |
| [Scenarios](SCENARIOS.md)                                 | End-to-end scenarios over the bundled data                         |
| [Auditor walkthrough](AUDITOR_WALKTHROUGH.md)             | The auditor's path through shares, snapshots, and workpapers       |
| [Vendor diligence use case](USE_CASE_VENDOR_DILIGENCE.md) | Just-in-time vendor diligence snapshots                            |
| [AWS + Snowflake demo](AWS_SNOWFLAKE_DEMO.md)             | Demo package for AWS evidence in Snowflake                         |
| [Live cloud POC](LIVE_CLOUD_POC.md)                       | Connecting a real AWS, Azure, or GCP account read-only             |
| [Shareable demo](SHAREABLE_DEMO.md)                       | Publishing a demo link for evaluators                              |
| [Shareable POC hosting](SHAREABLE_POC_HOSTING.md)         | Hosting a proof of concept                                         |

## Operate

| Guide                                                                    | Covers                                                  |
| ------------------------------------------------------------------------ | ------------------------------------------------------- |
| [Deployment](DEPLOYMENT.md)                                              | Self-hosted, hosted, and existing-lake deployment paths |
| [Server auth](SERVER_AUTH.md)                                            | SSO (OIDC, SAML), roles, API keys, hosted credentials   |
| [Connector credentials](CONNECTOR_CREDENTIALS.md)                        | Per-source credential setup                             |
| [Continuous ingestion](CONTINUOUS_INGESTION.md)                          | Scheduled sync and evaluation                           |
| [Operations contracts](OPERATIONS_CONTRACTS.md)                          | Generation archival, retention, integrity checkpoints   |
| [Evidence recovery](EVIDENCE_RECOVERY.md)                                | Recovery and external checkpoints                       |
| [DuckDB exports](DUCKDB_EXPORTS.md)                                      | DuckDB projection recovery                              |
| [Audit scale](AUDIT_SCALE.md)                                            | Large-volume ingestion, evaluation, and synthetic data  |
| [Commercial hosted](COMMERCIAL_HOSTED.md)                                | Gated hosted features: invites, limits, SCIM, billing   |
| [Release readiness](RELEASE_READINESS.md)                                | Release gates and what they prove                       |
| [Backup and restore](runbooks/BACKUP_RESTORE.md)                         | Backing up the lake and app database                    |
| [HA and read replicas](runbooks/HA_READ_REPLICAS.md)                     | Deployment topology and the single-writer boundary      |
| [Connector sync observability](runbooks/OBSERVABILITY_CONNECTOR_SYNC.md) | Connector sync dashboards                               |
| [Headless connector setup](playbooks/HEADLESS_CONNECTOR_SETUP.md)        | Configuring connectors without the console              |
| [HRIS personnel audit](playbooks/HRIS_PERSONNEL_AUDIT.md)                | HR systems and offboarding checks                       |

## Evaluate

| Guide                                                             | Covers                                       |
| ----------------------------------------------------------------- | -------------------------------------------- |
| [Evaluation contract](EVALUATION_CONTRACT.md)                     | What an evaluation guarantees                |
| [Evidence evaluation semantics](EVIDENCE_EVALUATION_SEMANTICS.md) | How evidence states become results           |
| [Assessment generations](ASSESSMENT_GENERATIONS.md)               | Publication and failure contracts            |
| [Collection completeness](COLLECTION_COMPLETENESS.md)             | Partial and blocked collection               |
| [Population reconciliation](POPULATION_RECONCILIATION.md)         | Reconciling the evidence population          |
| [Control test workpapers](CONTROL_TEST_WORKPAPERS.md)             | Control design and period testing            |
| [Governed remediation](GOVERNED_REMEDIATION.md)                   | Exceptions and remediation                   |
| [Audit readiness](AUDIT_READINESS.md)                             | Audit-readiness API and audit room           |
| [GRC automation](GRC_AUTOMATION.md)                               | The automated compliance loop and known gaps |
| [Common control framework](COMMON_CONTROL_FRAMEWORK.md)           | Safeguards, families, and categories         |
| [CCF assessment reads](CCF_READS.md)                              | Reading CCF results                          |
| [CCF risk monitoring](CCF_RISK_MONITORING.md)                     | Risk prioritization and ongoing monitoring   |
| [CCF AI context](CCF_AI_CONTEXT.md)                               | AI inventory and deployment context          |
| [Framework packs](FRAMEWORK_PACKS.md)                             | Pack contents, manifests, and gaps           |
| [Framework coverage](FRAMEWORK_COVERAGE.md)                       | Generated per-framework coverage matrix      |
| [Mapping review](MAPPING_REVIEW.md)                               | Reviewing proposed safeguard mappings        |
| [Catalog versioning](CATALOG_VERSIONING.md)                       | Catalog versions and audit pinning           |
| [AI bill of materials](AIBOM.md)                                  | AI inventory evidence                        |

## Integrate

| Guide                                                                | Covers                                                   |
| -------------------------------------------------------------------- | -------------------------------------------------------- |
| [Connectors](CONNECTORS.md)                                          | Connector catalog, release stages, and access model      |
| [Adding connectors](ADDING_CONNECTORS.md)                            | Writing a connector adapter                              |
| [AWS connector architecture](aws-connector-architecture.md)          | How the AWS connector collects                           |
| [Repository governance connector](REPO_GOVERNANCE_CONNECTOR.md)      | GitHub and GitLab governance and public repository audit |
| [Ingestion and idempotency](INGESTION_CONNECTORS_IDEMPOTENCY.md)     | Ingestion, connectors, and idempotency                   |
| [Bring your own lake](BRING_YOUR_OWN_LAKE.md)                        | Existing-lake readers, lake mappings, OCSF presets       |
| [Security data lakes](HERO_DATA_LAKES.md)                            | Supported lakes and warehouses                           |
| [Iceberg REST](ICEBERG_REST.md)                                      | Iceberg REST evidence publication                        |
| [Parquet export](PARQUET_EXPORT.md)                                  | Portable evidence with Parquet                           |
| [OSCAL export](OSCAL_EXPORT.md)                                      | Component definitions and assessment results             |
| [Webhooks](WEBHOOKS.md)                                              | Outbound event delivery                                  |
| [CI gate](CI_GATE.md)                                                | Failing a pipeline on posture                            |
| [CI posture gate playbook](playbooks/CI_POSTURE_GATE.md)             | Setting up the gate in CI                                |
| [Headless GRC](HEADLESS_GRC.md)                                      | API, MCP, and agent architecture                         |
| [Agent harness](AGENT_HARNESS.md)                                    | Persisted agent runs and approvals                       |
| [Agent API](api/AGENT_API.md)                                        | The v1 contract for humans and agents                    |
| [Agent skills](api/AGENT_SKILLS.md)                                  | Agent skill catalog                                      |
| [MCP evidence and approvals](cookbook/MCP_EVIDENCE_AND_APPROVALS.md) | MCP cookbook for evidence requests and approvals         |
| [API v1 migration](API_V1_MIGRATION.md)                              | Console migration to `/api/v1`                           |

## Security

| Guide                                                        | Covers                                  |
| ------------------------------------------------------------ | --------------------------------------- |
| [Trust boundaries](THREAT_MODEL.md)                          | Threat model and trust boundaries       |
| [Dependency security](DEPENDENCY_SECURITY.md)                | Dependency security scope               |
| [Third-party assets](THIRD_PARTY_ASSETS.md)                  | Policy for third-party logos and assets |
| [Benchmarks](BENCHMARKS.md)                                  | Validation and benchmark plan           |
| [Artifact hashing benchmark](benchmarks/ARTIFACT_HASHING.md) | Artifact hashing memory benchmark       |
| [CCF pipeline benchmark](benchmarks/CCF_PIPELINE.md)         | Bounded CCF pipeline measurements       |

## Reference

Several pages describe the architecture at different depths; start with
[Architecture](ARCHITECTURE.md).

| Guide                                                    | Covers                                         |
| -------------------------------------------------------- | ---------------------------------------------- |
| [Architecture](ARCHITECTURE.md)                          | Component map, module boundaries, design rules |
| [Components](architecture/COMPONENTS.md)                 | Component reference                            |
| [Data flow](DATA_FLOW.md)                                | Where evidence is stored and how it moves      |
| [Data model](DATA_MODEL.md)                              | Evidence, controls, tests, and snapshots       |
| [Product artifacts](PRODUCT_ARTIFACTS.md)                | Files and outputs TrustOps produces            |
| [Console UX](CONSOLE_UX.md)                              | Console operator and contributor guide         |
| [Visual system](VISUAL_SYSTEM.md)                        | Console layout and components                  |
| [Brand](BRAND.md)                                        | Name, voice, and brand constants               |
| [Diagram index](diagrams/README.md)                      | All diagrams                                   |
| [Architecture: local mode](diagrams/architecture.md)     | File-backed architecture                       |
| [ASCII system map](diagrams/ascii-system-map.md)         | Text system map                                |
| [Agent workflow](diagrams/agent-workflow.md)             | Persisted agent harness flow                   |
| [Identity and auth](diagrams/auth-identity.md)           | Identity and auth boundary                     |
| [Connector ingestion](diagrams/connector-ingestion.md)   | Read-only connection model                     |
| [Core GRC loop](diagrams/core-grc-loop.md)               | Sync to auditor-ready proof                    |
| [Data model diagram](diagrams/data-model.md)             | Analytics lake in local mode                   |
| [Deployment models](diagrams/deployment-models.md)       | Deployment options                             |
| [Dual lakehouse](diagrams/dual-lakehouse.md)             | Snowflake and ClickHouse roles                 |
| [Evaluation lifecycle](diagrams/evaluation-lifecycle.md) | Evaluation stages                              |
| [Hosting](diagrams/hosting.md)                           | Hosting model                                  |
| [Unified data model](diagrams/unified-data-model.md)     | Single-page data model                         |
