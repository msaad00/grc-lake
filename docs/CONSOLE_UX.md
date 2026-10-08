# Console UX — operator and contributor guide

TrustOps ships a Next.js console at `/console/*` backed by `/api/v1/*` and legacy lake APIs. This doc maps routes to hooks and notes what is fully shipped vs API-only.

## Shell patterns

| Pattern                                  | Where                                       | Notes                          |
| ---------------------------------------- | ------------------------------------------- | ------------------------------ |
| `QueryState`                             | Data pages (evidence, graph, audit-room, …) | Loading / error / empty states |
| `PageHeader`                             | Most routes                                 | Eyebrow, title, actions        |
| `SavedViewsBar` + `TagFilterBar`         | Evidence, controls, violations              | Persisted filters              |
| `usePlatformStream` / `usePostureStream` | Dashboard, audit-room, AI governance        | SSE live updates               |
| `CommandPalette` + `Sidebar`             | Global                                      | 28-route navigation            |

## Route map

| Route                      | Shipped UI               | Primary API / hooks                                                                        | Notes                               |
| -------------------------- | ------------------------ | ------------------------------------------------------------------------------------------ | ----------------------------------- |
| `/console/dashboard/`      | Posture, proof, fix-next | `usePosture`, `useControlTests`, `useIngestionStatus`, `useFrameworks`, `usePostureStream` | Trust Home                          |
| `/console/onboarding/`     | First-run onboarding     | `usePocReadiness`                                                                          | Readiness deep-links                |
| `/console/poc/`            | Launch checklist         | `usePocReadiness`                                                                          | Copyable invite URLs                |
| `/console/demo/`           | Live demo landing        | `useAuthMethods`, `usePocReadiness`                                                        | Evaluator entry                     |
| `/console/deploy/`         | Deployment models        | —                                                                                          | Static OSS / hosted explainer       |
| `/console/pricing/`        | Redirect to deploy       | —                                                                                          | Not surfaced in OSS console         |
| `/console/trust-center/`   | Trust shares             | `useTrustShares`, `usePosture`, `useCreateTrustShare`, `useRevokeTrustShare`               | External share preview              |
| `/console/controls/`       | Control workbench        | `useControls`, `useControlTests`, `usePosture`, `useTags`, `useTagEntityIds`               | Saved views + tags                  |
| `/console/evidence/`       | Evidence room            | `useEvidence`, `useEvidenceFreshness`, `useControls`, `useTags`, `useTagEntityIds`         | Freshness column + filters          |
| `/console/violations/`     | Findings queue           | `useViolations`, `useControls`, `useTags`, `useTagEntityIds`                               | Sidebar: Findings                   |
| `/console/remediation/`    | Tasks + requests         | `useRemediationTasks`, `useEvidenceRequests`, `useControlExceptions`, mutations            | Three tabs                          |
| `/console/automation/`     | Workflow builder         | `useWorkflows`, `useWorkflowRuns`, `useActionCatalog`, save/run/approve mutations          | Sidebar: Workflows                  |
| `/console/connectors/`     | Connector registry       | `useConnectors`                                                                            | Drawer: configure / sync / probe    |
| `/console/frameworks/`     | Framework provenance     | `useFrameworks`, `useReadiness`                                                            | `?framework=` deep-link             |
| `/console/crosswalk/`      | Mapping coverage         | `useCrosswalk`, `useReviewedCrosswalk`, `useMappings`                                      | Heuristic + reviewed                |
| `/console/risks/`          | Risk register            | `useRisks`, CRUD mutations                                                                 | Full risk lifecycle                 |
| `/console/access-reviews/` | Certification campaigns  | `useAccessReviews`, `useAccessReview`, items/coverage mutations                            | Personnel workaround                |
| `/console/policies/`       | Policy library           | `usePolicies`, templates, attestations, publish mutations                                  | Template adopt flow                 |
| `/console/vendor-risk/`    | Vendor questionnaires    | `useVendorAssessments`, questionnaire mutations                                            | Third-party diligence               |
| `/console/auth/`           | Keys + users             | `useAuthMethods`, `useAuthWhoami`                                                          | Child panels for invites            |
| `/console/graph/`          | Compliance + repo graph  | `useComplianceGraph`, `useRepositoryGraph`                                                 | Repository governance workbench     |
| `/console/insights/`       | Trends                   | `useInsightsTimeseries`, `useInsightsRemediation`, `useCaptureMetricMutation`              | Child charts for SLA heatmap        |
| `/console/audit-room/`     | Audit readiness          | `useAuditReadiness`, `usePlatformStream`                                                   | Strips: ingestion, POA&M, personnel |
| `/console/ai-governance/`  | AI inventory             | `useAiInventory`, `usePlatformStream`                                                      | SSE `ai-governance` events          |
| `/console/audit-log/`      | Activity log             | `useAuditLog`                                                                              | Category filters                    |
| `/console/agents/`         | Governed runs            | `useAgentRuns`, create/approve mutations                                                   | Agent run drawer                    |
| `/console/login/`          | Sign-in                  | `useAuthMethods`, `useSessionFromKeyMutation`                                              | Outside main shell                  |
| `/console/trust/[token]`   | Public trust share       | —                                                                                          | `GET /api/public/trust/{token}`     |

**Shipped UI** = interactive page in the console shell. **API-only** = endpoint exists but no dedicated route (use MCP or curl).

## Audit-room strip walkthrough

The audit room composes multiple strips; each strip maps to a platform API:

| Strip              | API                                                      | SSE event         |
| ------------------ | -------------------------------------------------------- | ----------------- |
| Readiness score    | `GET /api/v1/platform/audit-readiness`                   | `audit-readiness` |
| Ingestion loop     | `GET /api/v1/platform/ingestion-status`                  | `ingestion`       |
| Personnel / access | `GET /api/v1/platform/audit-readiness` (personnel block) | —                 |
| POA&M workbench    | `GET /api/v1/gov-compliance/poam`                        | —                 |
| AI governance      | `GET /api/v1/platform/ai-governance`                     | `ai-governance`   |

Open `/console/audit-room/` with the golden fixture and forward port 8787 to verify strips render without overlap at desktop and mobile widths.

## Contributor notes

- Prefer `/api/v1/*` for new hooks; legacy `/api/*` remains for graph and crosswalk.
- Add new routes to `Sidebar`, `CommandPalette`, and `Breadcrumbs` together.
- Run `npm run lint` in `app/web` before opening console PRs.
- See [ROADMAP.md](../ROADMAP.md) for shipped work and remaining gaps.
