# Product Artifacts

This page is the product review index for the public repo.

## Product Experience

| Artifact                       | Path                                           |
| ------------------------------ | ---------------------------------------------- |
| Next.js GRC Lake workbench     | `app/web/src/app/`                             |
| Local console/API server       | `src/security_lakehouse/server.py`             |
| FastAPI server mode            | `src/security_lakehouse/server_app.py`         |
| Continuous assessment engine   | `src/security_lakehouse/assessment.py`         |
| CLI entry point                | `src/security_lakehouse/cli.py`                |
| Vendor diligence use case      | `docs/USE_CASE_VENDOR_DILIGENCE.md`            |
| Trust Home screenshot          | `docs/images/grc-lake-demo-dashboard.png`      |
| Workflow canvas screenshot     | `docs/images/grc-lake-demo-workflows.png`      |
| Graph workbench screenshot     | `docs/images/grc-lake-demo-graph.png`          |
| Framework workbench screenshot | `docs/images/grc-lake-demo-frameworks.png`     |
| Mapping review screenshot      | `docs/images/grc-lake-demo-mapping-review.png` |
| Control drawer screenshot      | `docs/images/grc-lake-demo-control-drawer.png` |
| Evidence room screenshot       | `docs/images/grc-lake-demo-evidence.png`       |
| Connector workbench screenshot | `docs/images/grc-lake-demo-connectors.png`     |
| Trust center screenshot        | `docs/images/grc-lake-demo-trust-center.png`   |

Run locally:

```bash
make smoke
grc-lake serve --lake build/lakehouse --port 8787
```

Then open:

```text
http://127.0.0.1:8787/
```

## API Surfaces

| Route                                     | Purpose                                        |
| ----------------------------------------- | ---------------------------------------------- |
| `GET /api/v1/posture/current`             | enveloped current posture and framework scores |
| `GET /api/v1/violations`                  | paginated open control and asset violations    |
| `GET /api/v1/controls`                    | paginated control workbench data               |
| `GET /api/v1/evidence`                    | paginated normalized evidence facts            |
| `GET /api/v1/assets`                      | paginated asset risk queue                     |
| `GET /api/v1/insights/timeseries`         | captured posture and trend metrics             |
| `GET /api/v1/public/trust-shares/{token}` | token-scoped auditor posture view              |
| `POST /api/v1/snapshots`                  | point-in-time assessment snapshot              |

See [Human and Agent API](api/AGENT_API.md).

## Diagrams

| Diagram                   | Path                                                                                |
| ------------------------- | ----------------------------------------------------------------------------------- |
| Modular architecture      | [ARCHITECTURE.md](ARCHITECTURE.md)                                                  |
| Data model                | [DATA_MODEL.md](DATA_MODEL.md)                                                      |
| Dual security data lake   | [dual-lakehouse.md](diagrams/dual-lakehouse.md)                                     |
| Evaluation lifecycle      | [evaluation-lifecycle.md](diagrams/evaluation-lifecycle.md)                         |
| Hosting model             | [hosting.md](diagrams/hosting.md)                                                   |
| ASCII system map          | [ascii-system-map.md](diagrams/ascii-system-map.md)                                 |
| SVG architecture visual   | [grc-lake-assessment-architecture.svg](images/grc-lake-assessment-architecture.svg) |
| Framework coverage matrix | [FRAMEWORK_COVERAGE.md](FRAMEWORK_COVERAGE.md)                                      |

## Data And Schema

| Artifact                    | Path                                          |
| --------------------------- | --------------------------------------------- |
| Raw evidence schema         | `data/schemas/raw-security-event.schema.json` |
| Normalized event schema     | `data/schemas/normalized-event.schema.json`   |
| Current posture schema      | `data/schemas/current-posture.schema.json`    |
| Violation schema            | `data/schemas/violation.schema.json`          |
| Framework registry          | `frameworks/registry.json`                    |
| Implemented control catalog | `controls/catalog.json`                       |
| Control mapping             | `mappings/control_map.json`                   |
| Framework coverage matrix   | `docs/FRAMEWORK_COVERAGE.md`                  |

## Security Data Lake Backends

| Backend    | Role                                      | Path                                         |
| ---------- | ----------------------------------------- | -------------------------------------------- |
| Snowflake  | governed evidence and audit views         | `deploy/snowflake/schema.sql`                |
| ClickHouse | high-volume telemetry and trend analytics | `deploy/clickhouse/schema.sql`               |
| Local      | developer/internal demo mode              | `build/lakehouse`, generated by `make smoke` |

## Agent Skills

| Skill                       | Path                                                |
| --------------------------- | --------------------------------------------------- |
| Security operations analyst | `agent-skills/security-operations-analyst/SKILL.md` |
| SOC 2 control analyst       | `agent-skills/soc2-control-analyst/SKILL.md`        |
| PCI DSS analyst             | `agent-skills/pci-dss-analyst/SKILL.md`             |
| ISO/IEC 27001 ISMS analyst  | `agent-skills/iso27001-isms-analyst/SKILL.md`       |
| AI governance analyst       | `agent-skills/ai-governance-analyst/SKILL.md`       |

Each framework-specific skill is guardrailed to use local evidence and official
source references, and to avoid invented controls or certification claims.

Framework support currently covers eight source-linked, readiness-gated
frameworks: SOC 2, NIST AI RMF, ISO/IEC 27001, HIPAA Security Rule, PCI DSS,
GDPR, EU AI Act, and ISO/IEC 42001. Framework visuals use exact official names,
approved NIST framework artwork, and project-owned icons where marks are
restricted or nonexistent. Certification seals are not bundled without terms
and attribution documented under [Third-Party Asset Policy](THIRD_PARTY_ASSETS.md).
