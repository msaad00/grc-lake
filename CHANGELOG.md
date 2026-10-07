# Changelog

All notable TrustOps changes are summarized here. Versions follow semver for the
Python package, Helm chart, and bundled web console.

## Unreleased

### Added

- Supporting and inherited mapping relationships remain visible without coverage credit or OSCAL implementation claims.
- Evidence-bound N/A, inherited, and compensating assessment context in period workpapers, preserved through independent human review without changing machine verdicts.

- Durable tenant-scoped background operations for console and remote MCP evaluation, connector sync, scheduler ticks, and snapshots, with idempotent acceptance and explicit interrupted-work recovery.

### Fixed

- Share rule-aware verdict evaluation between controls and CCF safeguards, preserve source-tenant freshness boundaries, and reject bronze pointers as proof of available source evidence.
- Keep excluded or unknown MFA populations out of passing coverage, and classify GCP organization policies by their relevant constraint and explicit unconditional enforcement.

- Resolve catalogs from the active user-installed wheel and add explicit, resumable quarantine of interrupted snapshot files without rewriting committed history.

- Accept normalized passing evidence in workpapers, preserve open POA&M items when evidence is unknown, reopen completed items on regression, and suppress readiness scores when framework coverage is insufficient.

- Reject every unauthenticated production-server entry point, require authenticated sessions for human mapping review, and restore tenant-scoped snapshot integrity reads.

- Stream bronze and silver integrity verification instead of retaining full evidence payloads, preserving hash linkage, duplicate detection, counts, and evidence-set digests.

- Remove an unused framework-score assignment flagged by CodeQL; retain control-risk scoring for capped and uncapped assessments.

- Patch the console build selector parser through scoped overrides while preserving generated CSS; retain the separate unpatched braces advisory in dependency security documentation.

- Restore the README distinction between assessing an existing evidence lake and collecting new evidence through connectors.

- Preserve flat-lake ownership and share revocation as tenants are added, isolate request audits, and enforce server-side auditor view scopes.
- Bound graph detail, index connector history, coalesce stream computation, and cache unchanged catalogs. Add verified generation archival with snapshot and reader protection.
- Carry control input digests and event-level OSCAL lineage, validate query filters, harden MCP schemas and tool authority, and correct packaged skills and AWS permissions.
- Clarify console permissions and approval eligibility, improve responsive overview and freshness detail, respect system theme, and refresh the concise README and synthetic demo screens.

- Preserve historical snapshot and workpaper recovery without rewriting recorded hashes, support independently retained integrity checkpoints, and reject malformed generation and integrity manifests.
- Keep scores consistent when finding details are capped; distinguish missing provider evidence, avoid duplicate control counts, and report incomplete connector pagination and unavailable factor reads explicitly.
- Pin mapping approvals to reviewed control versions, support explicit safeguard bindings, label the NIST 800-53B Moderate pack accurately, and reopen remediation tasks when published evidence regresses.
- Carry normalized v4 evidence availability through Parquet and Iceberg exports while preserving source account identities and generation tenant isolation.

- Correct ten SOC 2 criterion topics from the AICPA source manifest and regenerate catalog metadata without changing mapping review decisions.
- Require human SSO for exception approvals, remediation retests, access decisions, policy acknowledgments, and workflow gates. Reject self-verification and linked-task dismissal without an evidence retest.
- Keep the scheduler daemon alive after tick errors, fsync connector history, bound CronJob retries, and provide explicit runtime-tail recovery with preserved originals and deferred scheduling. Reject evidence timestamps that overflow UTC or freshness arithmetic.
- Report incomplete SPRS assessments without a numeric score, count only explicit current passes in metrics, bind share issuers to authenticated identities, and enforce framework scope with observed-versus-catalog coverage counts.

- Avoid repeated snapshot decoding and canonical hashing on unchanged history, allow concurrent verified readers, and decode only requested trend payloads after verification while retaining whole-chain tamper detection.

- Record failed agent decisions without blocking other proposals, and let independent SSO reviewers close abandoned execution claims without replaying side effects or racing a live worker.

- Route remote MCP reads and writes through authenticated APIs, reject incomplete remote configuration and credential-bearing redirects, and support explicitly configured private API destinations.

- Preserve evaluated control verdicts when activity observations are also present, while retaining unknown, observation-only, failure, and stale states. Incremental evaluation refreshes existing verdicts without rewriting historical generations.
- Accept changed connector records at the same source timestamp when their collection is newer, preventing alert status updates from blocking later syncs. Older redelivery cannot overwrite the newer collection; conflicting ties on both timestamps still fail without changing the store.
- Keep inventory observations unevaluated, respect configured failure thresholds, and include declared eligible assets without period evidence in workpaper sampling gaps.
- Keep declared workpaper assets in sampling even when evidence is missing or unbound; exclude only a known incompatible asset type established by the cutoff, preserving account isolation and earlier exports.
- Retain failed login attempts as observations, preserve GCP IAM conditions, and identify broad/public access grants and open repository alert severity.
- Reconcile missing HIPAA workstation, media, authentication, policy and documentation identities against eCFR, preserving historical catalog scope and proposed mapping review.
- Persist scheduler attempts before execution so failed or interrupted workflows, connector syncs, and lake evaluations respect their configured interval; reject corrupt scheduler state without discarding retry history.
- Read and index connector history once per status request, retain successful runs beyond the recent-history window, and reject malformed history instead of silently discarding it.
- Schedule registered tenant lakes in hosted root ticks with isolated state, locks, execution identity, and webhook attribution; authenticated Helm deployments now use explicit all-tenant scheduling.

- Atomically claim agent decisions across SQLite/PostgreSQL before execution, require independent SSO review, and retain interrupted claims for reconciliation. The console now reflects review eligibility and in-progress decisions.
- Preserve connector-local event identities through upsert, normalization, incremental evaluation, and lineage; reject conflicting equal-time observations and retain newer evidence on stale redelivery.
- Preserve UTC instants in DuckDB marts and sinks independently of connection timezone.
- Verify live assessment generations and ledger-backed snapshot history before export; detect changed normalized evidence and require workpaper HTML to match its JSON. Reject unexpected export files and symlinks.

- Retain API-key provenance in exchanged sessions, revoke derived access with the key, and reserve independent workpaper and mapping review for eligible SSO identities. Key issuance cannot impersonate another user.
- Claim workflow decisions durably before execution, bind them to reviewed content, and reject replay or retry of interrupted approvals.

- Reject ambiguous or non-standard JSON before API, CLI/MCP dispatch, and shared lake writes; validate evidence shapes and timezone-qualified timestamps consistently with packaged schemas.
- Serve dispatched API routes in live OpenAPI and fail explicitly on corrupt stored share records without rewriting evidence.
- Evaluate current freshness per source, asset, and evidence type so retained history cannot permanently stale a control. Compare timestamp instants in UTC and prevent future collection times from establishing freshness.

- Portable PostgreSQL Boolean migration defaults and migration/model index parity, with real PostgreSQL upgrade/downgrade and existing-data checks.
- Preserve percent-encoded database credentials and query parameters through Alembic configuration so migrations and server startup accept those connection URLs.
- Installed cloud-link templates and evidence schemas now ship as importable package resources; CI checks them against canonical sources.

- Export reproducible auditor workpapers with scoped citations, separate control and population conclusions, retained remediation receipts, and independent authenticated review. Add a synthetic walkthrough and artifact capture.

- Reconcile declared asset populations with sealed evidence, bounded gap details, freshness and collection-receipt checks, and explicit limits on inventory-completeness claims.

- Add reproducible CCF control test plans with separate design documentation, period samples, deviations, and explicit pending human review. Include five synthetic walkthrough controls.

- Require independent, authenticated, expiring exception approvals and fresh sealed-evidence verification before resolving control-linked remediation. Retain verification receipts and migrate legacy approvals to pending.

- Add `security-lakehouse --version` and `assessment status --format summary`, retaining JSON by default and showing unevaluated controls and full assessment totals.

- Exercise the built image through the Compose quickstart in CI, including readiness, golden posture, and volume persistence without reseeding after container recreation.

## 0.2.20 - 2026-10-03

- Package every framework source manifest and reject wheels with missing pack data, fixing installed demo and evaluation failures.

- Add dependency-aware deployment readiness, refresh the README product tour and demo screenshots, and align release artifacts.

- Read CCF summaries and asset pages from indexed, generation-pinned SQLite projections; preserve query semantics and fail closed on broken indexes.
- Refresh DuckDB sink tables atomically, remove obsolete rows, and reject cross-lake destination reuse; existing unowned destinations require a new database.
- Bind hosted assessments to the authenticated platform tenant and block ambient warehouse exports from tenant requests.

- Update urllib3, PyJWT, oauthlib, virtualenv, and brace-expansion to address dependency advisories.

- Preserve unknown evidence outcomes, refresh incremental assessments at freshness boundaries, and pin historical OSCAL findings to verified snapshot inputs.
- Publish explicit safeguard-to-asset evaluation and reviewed requirement rollups through the API, CLI, MCP, and Frameworks page, with observed-population limits.
- Reuse connector discovery across control tests, consolidate framework scoring and evaluation result serialization, and distinguish local publication from warehouse export failures.
- Reject unsupported Helm read replicas and multiple writers regardless of volume access mode; document current deployment and evaluation limits.

- CI type-checks the package with mypy (`make typecheck`).
- Workflow `action.connector_sync` no longer fails with an AttributeError
  after a successful sync.
- Snowflake and Databricks asset-risk rows with no status and a missing or
  non-numeric risk score are recorded as observed instead of failing the sync.
- An OpenAI-compatible model response whose first choice has no message is
  reported as a model error instead of an AttributeError.
- Posture gate fails closed: when an allowlist of failing controls is set and
  the control-tests request fails, the gate now fails instead of reporting zero
  failing tests, and failing tests beyond the fetched page count as unexpected
  instead of being dropped. Empty lists no longer crash on macOS bash 3.2.
- Hosted cloud linking: the console's Azure and GCP link forms collect the
  tenant's own app registration (tenant ID, client ID, and one secret,
  certificate, or federated token file reference) or service account to
  impersonate, validated in the browser and on the server with the readers'
  rules. Reference fields take env-var names only and show the tenant's
  `TRUSTOPS_TENANT_<ID>__` prefix, and connector form placeholders use it in
  hosted mode. `GET /api/v1/auth/whoami` reports `hosted` and
  `secret_ref_prefix`.
- The Azure admin-consent callback no longer copies the tenant it reports into
  connector options, and hosted mode offers no consent URL for an
  operator-owned multi-tenant app.
- Test reliability: the API rate-limit tests run on a frozen clock, and the
  connector registry tests restore process-global state and ignore connectors
  from installed packages.
- Framework packs: NIST SP 800-171 Rev 3 (all 97 requirements from NIST's
  OSCAL catalog, each with its Rev 2 predecessors from NIST's change
  analysis), EU NIS2 (Article 21(2)(a)-(j) measures and Article 23
  reporting) and EU DORA (99 financial-entity obligations across Articles
  5-30 and 45). Sources are pinned by sha256; every new CCF mapping is
  proposed, and requirements without an honest safeguard home are listed.
  CMMC 2.0 Level 2 stays on Rev 2.
- EU AI Act: `EU-AI-ACT-Art.49` carried the fundamental rights impact
  assessment title, which is Article 27. It is now "Registration" (version
  1.1.0; the old version stays in history), its risk-assessment mapping moved
  to the AI governance safeguard, and Article 27 is added.
- AI governance: 16 new life-cycle safeguards (evaluation, drift monitoring,
  AI incidents, model and dataset provenance, human oversight, and more), all
  proposed. NIST AI RMF coverage rises from 28 to 69 of 72 requirements and
  ISO/IEC 42001 from 26 to 37 of 39; the requirements left unmapped on
  purpose are listed in docs/CCF_AI_CONTEXT.md.
- Control categories: the 21 control families are grouped into 10 categories.
  `GET /api/v1/ccf/coverage` returns a `categories` ledger,
  `frameworks safeguards --format table` prints families under their category,
  OSCAL components carry a `trustops-category` property, and the console
  Control families tab groups families by category and links to each family's
  review queue.
- Fixed: a control family or category reported `state: reviewed` as soon as
  one of its mappings was reviewed, so 15 families and all 10 categories read
  as reviewed while most of their mappings were proposed. The state is now
  `reviewed` only when no mapping is proposed, `partially_reviewed` when some
  are, and `proposed_only` when none is reviewed.
- Adoption kit: a root `compose.yaml` (a loopback-only sample-data demo, and
  a `trustops-server` profile with authentication on), a
  [5-minute tutorial](docs/TUTORIAL_5_MIN.md), [CI gate](docs/CI_GATE.md)
  docs with a sample-data workflow, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT,
  and issue forms.
- Security: mapping-review endpoints return fixed error messages instead of
  exception text; the server logs only the exception class.
- Fixed: a lake with no evaluated controls reported Assessment score 100 and
  "Ready for review" (and fed that 100 into audit readiness). It now scores 0
  with posture state `not_evaluated`, shown as "Not assessed".
- Fixed: the AI governance page used stale framework ids and counted only
  evaluated controls as "mapped", so ISO/IEC 42001 and the EU AI Act read
  "0/0 mapped". Each pack now shows the requirements and safeguard-mapped
  counts the Frameworks page shows, a pass rate only when this lake has
  evidence, and packs with nothing evaluated no longer pull the governance
  score down as 0%. An inventory inferred from lineage no longer triggers the
  "no model inventory" gap.
- Console: "mapped" means mapped to a safeguard everywhere. The framework
  drawer's mapped count now matches the roster; official-source links read
  "source-cited" and the readiness gate reads "reviewed article mappings".
  A `/controls?id=` link to a control this lake has not evaluated (or an
  unknown id) says so and links to the requirement in Frameworks, and the
  crosswalk chips carry the framework for that link. "AI controls" becomes
  "AI safeguard mappings" and opens the AI governance review queue.
- Console: trust-center share links resolve in no-auth mode before the lake
  holds any data; the Azure link badge reads "No secrets stored" (a client
  secret is supported, only its env-var name is kept); date helpers show "—"
  for unparseable dates; identity marks meet 4.5:1 contrast, and the
  accessibility suite now checks color contrast, including /auth.
- Fixed: `GET /api/v1/policies?status=…` and
  `GET /api/v1/vendor-assessments?status=…` returned 500 for any status, which
  also broke the MCP `list_policies` status filter.
- Security: webhook delivery records store a fixed reason (for example "SSRF
  blocked" or the error class) instead of resolver and socket text, which
  could reveal the private address an internal hostname resolved to. Hosted
  Azure cloud links require the subscription ID to be a GUID, and a completed
  cloud-link session can no longer be completed again to overwrite its staged
  credentials.
- CI builds with the same uv version as the container image, and a test fails
  when the pins drift apart. The container's uv moves from 0.10.9 to 0.12.19
  and the `setup-uv` action from 7.6.0 to 10.2.0.
- The published image is multi-arch (`linux/amd64` and `linux/arm64`), so
  `docker compose up` runs natively on Apple silicon and Arm hosts.
- Console dependencies: Next.js 16.3.6, React Flow 12.12.0, framer-motion
  13.4.3, lucide-react 1.48, and TanStack Query 5.103.2.
- Console: GDPR, NIS2, and DORA use their own neutral marks instead of the EU
  AI Act badge; the crosswalk overlap matrices name each framework once, and
  the Control families tab states its category, family, and safeguard counts.
  README screenshots add the Control families tab and the crosswalk.

## 0.2.19 - 2026-09-28

- Operator note (hosted / multi-tenant server mode only; self-hosted
  single-tenant and CLI installs are unaffected): connector and workflow
  secrets now resolve only from tenant-prefixed variables
  (`TRUSTOPS_TENANT_<ID>__…`) or names the operator allowlists in
  `TRUSTOPS_CONNECTOR_SECRET_REFS` / `TRUSTOPS_WORKFLOW_SHARED_SECRETS`; move
  shared secrets before upgrading. Hosted AWS connectors need `role_arn` and
  `external_id`, GCP and BigQuery need `impersonate_service_account`, and Azure
  and Intune need a tenant-owned app registration. After rotating
  `TRUSTOPS_COOKIE_SIGNING_KEY`, run `frameworks review resign` once per tenant
  lake.
- Live-cloud readiness, verified against real AWS, Azure, and GCP tenants:
  `connectors probe` accepts the same credentials as sync (including a local
  CLI profile for AWS) and makes a real read-only call for Azure and GCP; GCP
  keeps collecting when an API is disabled or a permission is missing and
  reports it as a named coverage gap; connector errors say what to fix instead
  of only an exception name; and long asset IDs no longer collide, so every
  synced GCP row is counted.
- Console consistency: framework counts include only seeded packs (planned or
  superseded packs are listed separately), the superseded ISO/IEC 27701:2019
  row says so, badges use one set of labels, Preview has a keyboard-reachable
  explanation, and the overview and audit room name their different scores.
  Server-mode requests now record the signed-in user as the actor even if the
  request body names someone else. README screenshots are cropped to their
  content and include Mapping review and a phone-width overview.
- Org mapping review: your reviewers can approve, reject, or request changes
  to safeguard mappings for your tenant (console **Mapping review**, API
  `/api/v1/mapping-reviews/*`, CLI `frameworks review`). Decisions go to an
  append-only, hash-chained log in the tenant lake with reviewer, rationale,
  and time; `controls/safeguards.json` is never modified. Coverage, OSCAL, and
  snapshots report maintainer-reviewed, org-reviewed, and rejected separately.
  New `compliance_reviewer` role and `mapping_review` scope; API keys, agents,
  and MCP tools can list the queue but never decide.
- Hosted tenant isolation: in server mode, connector secret references resolve
  only under the tenant's `TRUSTOPS_TENANT_<TENANT_ID>__` prefix or the new
  operator allowlist `TRUSTOPS_CONNECTOR_SECRET_REFS`, and server secrets
  (`TRUSTOPS_*`, `DATABASE_*`, `AWS_*`, `STRIPE_*`, and similar) are always
  refused. Cloud readers need delegated access: AWS `role_arn` plus
  `external_id`, GCP and BigQuery `impersonate_service_account`, a tenant
  `kubeconfig_ref` for Kubernetes. Local Parquet paths are scoped to
  `$TRUSTOPS_LAKE_LOCAL_ROOT/<tenant_id>`. Iceberg REST and Glue readers keep
  only vended credentials from catalog metadata and accept only object-store
  locations (`s3://`, or the warehouse's `gs://`); local `file:` warehouses
  stay available in local and CLI mode only. Local and CLI runs are otherwise
  unchanged. Operator note: hosted
  tenants whose connectors name a shared or default secret must move it to a
  tenant-prefixed variable or add it to `TRUSTOPS_CONNECTOR_SECRET_REFS`; see
  docs/SERVER_AUTH.md#hosted-connector-credentials.
- Hosted Azure isolation: in server mode `azure-posture` and `intune-devices`
  authenticate only as the customer's own Entra app registration (`tenant_id`,
  `client_id`, and one of `client_secret_ref`, `client_certificate_ref`, or
  `federated_token_file_ref`). `DefaultAzureCredential`, the `az` CLI login,
  and the server-wide `AZURE_SUBSCRIPTION_ID`/`AZURE_TENANT_ID` overrides are
  refused for tenants. Local and CLI runs keep `DefaultAzureCredential`.
  Operator note: hosted Azure and Intune connectors that relied on the
  server's identity stop syncing until the tenant configures an app
  registration and the operator provisions its secret under the tenant prefix.
- Hosted workflow secrets: in server mode `{{secret.NAME}}` resolves from the
  calling tenant's `TRUSTOPS_TENANT_<TENANT_ID>__SECRET_<NAME>`, not the shared
  `TRUSTOPS_SECRET_<NAME>`. Operator note: before upgrading, copy each
  tenant's workflow secrets to its prefixed name (tenant `acme`:
  `TRUSTOPS_SECRET_SLACK_WEBHOOK` becomes
  `TRUSTOPS_TENANT_ACME__SECRET_SLACK_WEBHOOK`), or list a secret that is
  deliberately shared by every tenant in `TRUSTOPS_WORKFLOW_SHARED_SECRETS`.
  Unmigrated webhook, Slack, and Jira actions fail without sending. Local
  mode is unchanged.
- Mapping review: the new `frameworks review resign` command
  (`--lake <dir> --previous-key-env <NAME>`) re-signs the decision-log tip
  after `TRUSTOPS_COOKIE_SIGNING_KEY` is rotated. It verifies the hash chain and the old tip MAC with the
  previous key first, refuses and writes nothing if either fails, and records
  a `tip_resigned` entry in the workbench audit log. Operator note: after
  rotating the key, run it once per tenant lake. See
  docs/MAPPING_REVIEW.md#rotating-the-signing-key.
- SSRF guard: 6to4 (`2002::/16`) and Teredo (`2001::/32`) addresses are
  judged by the IPv4 addresses they embed, so one that tunnels to a private,
  loopback, or metadata IPv4 is refused on every supported Python version.

## 0.2.18 - 2026-09-27

- Operator note: this release adds database migration `0020`
  (`saml_assertion_replays`). The server applies it at startup; with more than
  one replica, upgrade with a single replica first.
- New connectors (preview): Jamf Pro (device encryption, OS patch level,
  screen lock, firewall, managed state), CrowdStrike Falcon (sensor coverage,
  prevention policies, detections), Kubernetes (cluster-admin bindings, pod
  security, network policies, image registries; new optional `kubernetes`
  extra), and KnowBe4 (training completion and phishing results). All are
  read-only, use credential references, and report against existing control
  IDs. Connectors not yet verified against a live tenant carry
  `release_stage: "preview"` and a Preview badge in the console.
- ISO/IEC 27701:2025 limited privacy pack (`iso-27701-2025`): 10 of the 78
  Annex A controls, each with its identifier and short title confirmed by two
  independent non-vendor sources; the other 68 are listed as gaps. The
  withdrawn 2019 edition stays planned. New privacy evidence types, connector
  hints, and proposed safeguard mappings.
- Docs: the README leads with the two evidence modes (ingest, or read the lake
  you already run), a self-host table, and a plain scope table, with each fact
  stated once. Connector, roadmap, deployment, and product-status docs match the
  live catalog (28 contracts, 25 executable) and coverage (17 packs, 2,031
  requirements; NIST RMF mapped, ISO 27701:2025 limited), and stale "scaffold"
  wording is gone. The Databricks reader is now marked preview in the connector
  catalog, matching its docs.
- Console visual system: neutral light and dark themes with clear elevation
  steps (page, rail, card, raised) and visible borders; one brand accent for
  primary actions, the active page, links, and focus; and a status palette
  (success, warning, serious, danger, info) whose tinted chips meet WCAG AA in
  both themes. Light mode now has a light shell. A contract test checks every
  text/surface pair.
- Overview is decluttered so each number appears once: one status line, KPI
  tiles with a label, number, one line of context, and an optional meter, a
  framework list with a single sort control, and a five-row findings preview
  (severity, title, control ID) that no longer clips. The collapsed
  "Operational detail" section and the duplicate Exports tab are gone; owner,
  environment, and source live in the finding drawer.
- The finding drawer is grouped into Summary, Details, Remediation (with
  button actions), and Triage. Page headers, tabs, filters, and the pipeline
  stepper share one pattern across routes, and graph layers use validated
  categorical colours with dimmed nodes that stay legible.
- Golden demo data: each event's source now follows its event type (a model
  drift alert comes from the SIEM, not AWS Config).
- Deepen the common control framework: 34 new safeguards split thin families
  (governance, incident response, privacy, change, vulnerability, configuration,
  secure development, architecture, processing integrity, third-party risk,
  system maintenance) into their sub-objectives, and map 43 of the 47 NIST RMF
  (SP 800-37 Rev 2) tasks with task-level citations. All 351 new mappings are
  `proposed`, so evaluatable coverage rises from 813 to 991 requirements while
  attestable (reviewed) coverage stays at 350.
- Bring your own lake (experimental): a declarative lake mapping spec maps
  existing tables to evidence, so the Snowflake, Databricks, and ClickHouse
  readers no longer need TrustOps-shaped views. Mappings compile to read-only,
  parameterized queries. Built-in OCSF presets cover Authentication, Account
  Change, API Activity, and Detection, Vulnerability, and Compliance Findings
  (OCSF 1.1.0), plus the legacy Security Finding (OCSF 1.0.0-rc.2).
  `security-lakehouse lake map --dry-run` previews mapped rows and errors. New
  preview readers: `iceberg-parquet-lake` (Iceberg via AWS Glue, including
  Amazon Security Lake, or REST catalogs, and Parquet on S3) and
  `bigquery-evidence-lake` (new optional `bigquery` extra). See
  docs/BRING_YOUR_OWN_LAKE.md.
- Widen mapping coverage on the existing safeguards: 180 title-theme mappings
  for ISO 27001:2022 (57 to 81 of 93), NIST CSF 2.0 (79 to 101 of 106),
  ISO 27017 (29 to 44 of 47), NIST AI RMF (20 to 28 of 72), FedRAMP Moderate
  (207 to 262 of 287, with their 800-53 twins), and GDPR (18 to 19 of 20),
  plus cited NIST RMF tasks P-3, P-14, and M-7 (43 to 46 of 47). All are
  `proposed`: evaluatable coverage rises from 991 to 1174 requirements while
  attestable (reviewed) coverage stays at 350.
- Outbound HTTP connects to the IP address it validated. Connectors, webhooks
  and workflow actions resolve each host once per connection, require every
  answer to be public, and open the socket to that address, so a DNS answer
  that changes between the check and the connect (rebinding) cannot reach a
  private address, including on redirect hops. TLS SNI and certificate checks
  still use the hostname. Requests through an operator egress proxy connect to
  the proxy.
- SAML replay protection is shared across replicas: consumed assertion IDs are
  stored in the application database under a unique constraint, so a replay to
  a different replica is rejected. A database error rejects the login.
- The golden demo names its assets ("Customer records bucket", "Risk scorer
  model"), and the console shows those names in findings, evidence, drawers,
  the command palette, AI inventory and the graph, keeping the stable IDs in
  drawers and tooltips. Raw events may set the optional `entity.asset_name`;
  the API returns it as `asset_name`. Normalized events and their Parquet and
  Iceberg exports are unchanged.
- `fixtures load --rebase-times` puts the newest demo row three hours back
  instead of one, so the demo's freshness counts and posture score stay the
  same for about a day instead of changing minute to minute after a load.
- `frameworks sync` reports drift only when a source's content hash changes;
  `pulled_at` now records when the current content was first seen, so the
  scheduled job no longer opens a PR for every run.
- The package declares its license as the SPDX expression `Apache-2.0`
  (wheel metadata 2.4, `License-Expression`); building needs setuptools 77 or
  newer.

## 0.2.17 - 2026-09-27

- Operator note: this release adds database migration `0019` (a
  `resolution_note` column on remediation tasks). The server applies pending
  migrations automatically at startup, so back up the database before
  upgrading. With more than one replica, upgrade with a single replica first
  (or scale to one) so only one process runs the migration.
- Add SCIM provisioning and Billing panels to the console's Auth page for
  commercial hosted admins: create SCIM tokens with a one-time reveal, revoke
  them, see plan and access state, and open Stripe checkout or the customer
  portal. Both panels stay hidden on OSS installs. Listing SCIM tokens now
  returns 501 when SCIM is disabled, matching create.
- Console polish: dark-mode contrast across every route, layouts that fit at
  390px, a graph that wraps wide ranks instead of shrinking to unreadable zoom,
  a paginated crosswalk, sign-in options first on phones, and one page width
  and gutter scale. `/api/v1/platform/usage` returns 501 instead of 404 without
  commercial hosting, and the POC "Agent/API access" step links to the console.
- Stop overclaiming readiness, freshness, and review status. Readiness numbers
  change on upgrade: a framework is ready only when at least 50% of its catalog
  controls are assessed (not on score alone), controls without evidence are
  `missing` rather than fresh, the audit score no longer counts shipped product
  features, and the crosswalk shows each mapping's real status (reviewed or
  proposed). The readiness payload adds per-framework coverage and
  `framework_ready_criteria`.
- Persona-driven console fixes: findings carry into tasks and link back,
  resolving a task records proof in the new `resolution_note` field, owner
  filters, trust shares with a copyable URL and preview (public shares no
  longer expose violation or stale counts), adoptable policy templates, and
  refreshed demo data.
- Reviewers can reject a proposed agent decision with a reason
  (`POST /api/v1/agent-runs/{id}/decisions/{i}/reject` and a matching MCP tool);
  a rejected decision never runs and approving it returns 409. The OpenAPI
  document is regenerated. Frameworks and Crosswalk now name their mapping
  units, and console pages mount once per navigation, so input typed right
  after a navigation is no longer lost.
- Security fixes. ClickHouse evidence-lake cursors are sent as typed query
  parameters and every query runs with `readonly=1` (a crafted row value could
  previously break out of the SQL literal). SAML responses must answer a login
  this server started and each assertion is accepted once; IdP-initiated login
  now requires `TRUSTOPS_SAML_ALLOW_IDP_INITIATED=true`. Self-service signup
  fails closed without `TRUSTOPS_SIGNUP_SECRET` unless
  `TRUSTOPS_ALLOW_OPEN_SIGNUP=1`. The local stdlib server rejects foreign
  `Host` and cross-origin `Origin` headers, requires JSON bodies, and caps
  request size. Rate limits key on the client until a bearer token
  authenticates. Egress checks block all non-global addresses (including
  CGNAT). Invite acceptance records the new user, returns 409 for existing
  members, and validates the role.
- Console: mobile navigation drawer, one name per page across the sidebar,
  headings, and command palette, Graph and Settings in the sidebar, keyboard
  and screen-reader support in the shell and command palette, contrast fixes,
  loading and error states where pages showed empty data, and a flat KPI strip
  on the overview. README, roadmap, and deployment docs now match the code,
  and README screenshots are captured from one frozen dataset in both themes.
- Harden the release pipeline: a tag publishes only a commit that is on main
  and passed CI, and only when the package, chart, console, `package.json`,
  and changelog agree on the version. Wheels, sdists, and the container image
  carry signed build provenance; the image also carries an SBOM, and the
  release attaches a CycloneDX SBOM of the Python dependencies. Fixable HIGH or
  CRITICAL image vulnerabilities fail CI and block the release. Workflow
  actions and container base images are pinned by digest. `latest` moves only
  on stable releases. Framework sync retries rate-limited or failing regulator
  sites and reports per-source errors without failing the job.

## 0.2.16 - 2026-09-24

- Add production SCIM 2.0 for commercial hosted tenants: per-tenant hashed
  bearer tokens with rotation, raw `application/scim+json` responses, user
  filters, PUT/PATCH in the shapes Okta and Entra ID send, soft delete that
  keeps the audit trail, and Groups whose membership maps to TrustOps roles
  through `TRUSTOPS_SCIM_ROLE_MAP`.
- Add Stripe billing for commercial hosted tenants: Stripe Checkout and the
  customer portal, signature-verified and idempotent webhooks that re-read the
  current subscription, plan tier driven by the subscription price, and a
  past-due grace period followed by read-only access (data and reads kept).
- Add a Databricks evidence-lake reader (preview) over Unity Catalog views via
  the SQL Statement Execution API with OAuth M2M, plus a bootstrap SQL script;
  live-workspace verification is pending.
- NIST SP 800-53 mappings that duplicate a human-reviewed FedRAMP Moderate
  mapping now inherit that review (attestable 254 -> 350 of 2,021), and NIST AI
  RMF titles use the official NIST AI 100-1 subcategory statements.

## 0.2.15 - 2026-09-24

- Add the full NIST SP 800-53 Rev 5.2.0 catalog (1,014 active controls and
  enhancements, 20 families) generated from a pinned official OSCAL commit,
  with LOW/MODERATE/HIGH/PRIVACY baseline tags, and the NIST Risk Management
  Framework (SP 800-37 Rev 2, all 47 tasks). Both are source-reconciled and
  proposed, not human-reviewed.
- Add CIS Controls v8.1 at the control level (all 18 controls) and a governed
  CCF family taxonomy (`controls/families.json`, 21 families with NIST 800-53
  and CIS crosswalks) replacing a catch-all family.
- Add proposed CCF mappings that raise evaluatable coverage for ISO 27001
  Annex A (11 → 43 of 93), NIST AI RMF (10 → 20), and NIST CSF 2.0 (29 → 46);
  attestable (reviewed) coverage is unchanged.
- Cite PCI DSS v4.0.1 across all 12 principal requirements via versioned
  control successors; document why SOC 1 stays planned (no official control
  catalog).
- Add Microsoft Intune device-posture and BambooHR, Rippling, and Workday
  (RaaS) employment-record connectors with a minimal PII boundary, and an
  offboarding check that flags terminated employees whose Okta or Google
  Workspace account can still sign in.
- Let installed packages register connector catalog metadata through a
  `trustops.connector_catalog` entry-point group.
- Fix: readiness no longer treats proposed mappings as reviewed; framework
  coverage reports reviewed identifier mappings separately from
  source-cited ones; the review queue no longer lends a crosswalk citation to
  title-theme mappings; OAuth connectors (including `identity-provider`) can be
  enabled from the console; `controls/families.json` ships in the wheel.

## 0.2.14 - 2026-09-23

- Export OSCAL Component Definition and Assessment Results (NIST's
  control/assessment interchange format) via a new CLI command and API
  endpoints, so auditor tooling and other GRC platforms can consume TrustOps
  assessment data without a bespoke adapter. Only reviewed (human-confirmed)
  safeguard mappings are represented as implemented requirements.
- Let third-party packages register connectors via a `trustops.connectors`
  Python entry-point group, alongside the existing in-repo adapters, without
  forking the repository.
- Add outbound event webhooks (`finding.created`, `assessment.completed`,
  `control.failed`) with HMAC-signed, retried delivery and a dedicated,
  opt-in destination allowlist separate from workflow-automation egress.
- Convert 12 of 13 framework packs from bespoke Python functions to
  JSON manifests read by a shared builder, verified row-identical
  (including every control id) against the prior generated output.

## 0.2.13 - 2026-09-22

- Serialize hash-chain writers with a cross-process lock so concurrent
  violation-triage and assessment-snapshot requests can no longer fork the
  tamper-evident audit chain.
- Resolve two `anyio` CVEs (CVE-2026-63374, CVE-2026-64847) via a transitive
  dependency bump; no functional changes.
- Show the product tour screenshots by default in the README instead of
  behind a collapsed section.
- Promote 209 Common Control Framework safeguard mappings from proposed to
  reviewed across CMMC 2.0, ISO 27017, FedRAMP Moderate, ISO 42001, and CIS
  AWS, raising audit-defensible (attestable) coverage from 4.8% to 27.0%.
- Routine web dependency updates (`@tanstack/react-query`, `framer-motion`,
  `lucide-react`, `tailwind-merge`, `@types/node`, `autoprefixer`).

## 0.2.12 - 2026-09-15

- Lead the dashboard overview with overall posture, an assessment score out of 100,
  and a prominent control pass rate with passing-test counts. Keep findings and
  exports alongside them, and distinguish unevaluated controls from a zero pass rate.
- Unify overview cards with matching navy surfaces, labeled test-outcome and
  finding-severity charts, and aligned actions. Preserve compact tablet layouts
  and mobile accessibility. Test outcomes outside pass/fail/warning remain Other.
- Keep control-drawer status badges readable beside long control titles.
- Refresh release-readiness documentation and align package, console, and Helm
  versions. Assessment calculations and connector behavior are unchanged.

## 0.2.11 - 2026-09-14

- Compact the app header and assessment overview, with direct workspace links,
  expandable assessment details, and an account menu available on mobile.
- Read the versioned health response correctly so a healthy API is not shown
  as unavailable in the console header.
- Refresh selected workflow-node parameters when the loaded workflow changes,
  and clear test results associated with the previous parameters.
- Replace an accepted invite's URL with sign-in so Back does not reopen the
  consumed invite link. Preserve full session-cache reset on authentication loss.
- Stabilize console effect dependencies and workflow keyboard handlers.
- Restore the README cloud/vendor banner and visible framework and common-control
  sections, with generated mapped-versus-reviewed coverage totals.
- Update compatible console dependencies together, align React and React DOM,
  and patch transitive JavaScript dependency vulnerabilities. Retain the MCP 1
  compatibility bound because the MCP 2 entry point is incompatible.
- Group routine dependency updates weekly by ecosystem, limit outstanding
  version-update PRs, and group security fixes separately.

## 0.2.10 - 2026-09-14

- Reject truncated, unknown-completeness, and malformed public repository trees
  before replacing collected evidence.
- Stop saving source-text excerpts in public repository audit events. Keep paths
  and sample hashes; existing collected evidence is not rewritten.

- Stream artifact SHA-256 checks through a reusable 1 MiB buffer during evidence
  integrity creation/verification, generation sealing/verification, and Parquet
  export. Preserve digest formats, tamper detection, and publication failure
  behavior. Add a reproducible synthetic hashing memory benchmark; full-pipeline
  capacity, live accuracy, and cost savings remain unverified.

## 0.2.9 - 2026-09-13

- Add an optional, generation-pinned Parquet evidence export with explicit tenant
  checks, private atomic publication, provenance, and independent DuckDB parity
  tests.
- Add optional Iceberg REST publication to one tenant-scoped evidence table.
  Verify local Polaris commits and DuckDB reads, retained-snapshot retries,
  historical reads, nullable schema additions, and catalog permission denial.
- Require externally issued bearer tokens, HTTPS outside explicit loopback tests,
  bounded requests, and confirmed snapshot provenance. Reject redirects, remote
  authentication plugins, incompatible schemas, and silent concurrent replacement.
- Include the optional export dependencies in the container and align package,
  console, chart, and documentation at 0.2.9. Constrain container dependencies to
  the audited lockfile. Cloud object storage, distributed
  scale, live accuracy, and cost savings remain unverified.
- Allow empty assessments to create typed DuckDB tables without failing on
  empty insert batches.

## 0.2.8 - 2026-09-13

### Fixed

- Stop incomplete pagination and failed required GCP reads before replacing
  retained evidence. Reject invalid evaluation rules and duplicate control IDs.
  Preserve unknown/retired controls as not evaluated instead of applying a default rule.
- Publish verified assessment generations through an atomic current pointer;
  interrupted publication preserves the prior generation.
- Compute AI framework posture from passing controls, separately from evidence
  presence. Correct CSF 2.0 identifiers against the pinned NIST source and retain
  prior control definitions in history.
- Include safeguard definitions in catalog hashes and installed packages. Ship
  framework pack data, equivalence mappings, history, fixtures, and agent skills.
- Restore supported Azure resource-policy and MCP dependency bounds.

### Changed

- Apply the TrustOps identity across the console, README, shared images, and MCP.
  Add independent collapsible dashboard panels, readable framework rows,
  control-family icons, contextual triage, and reviewable evidence requests.
- Organize the README into a short setup path and expandable reference sections.
- Add proposed AI inventory/context and risk/monitoring safeguards. The catalog
  now has 44 safeguards mapping 559/942 requirements; 45 remain reviewed.
- Add the TrustOps operator skill alongside six specialist skills. Document
  evidence completeness, scoped conclusions, authorization, and retry boundaries.

Mapping coverage does not establish framework compliance. Live precision,
recall, production capacity, and vendor cost savings have not been established;
the benchmark protocol separates those measurements from synthetic validation.

## 0.2.7 - 2026-09-01

Release theme: **secure dependencies + clearer first-run story**. Restores the
release security gate and makes the README's product journey readable at a
glance without changing TrustOps proof semantics.

### Security

- Raised the optional Snowflake connector floor to 4.7.1 and regenerated the
  lockfile, replacing 4.6.0 after `pip-audit` identified CVE-2026-15925.

### Added

- Common Control Framework safeguards for controlled maintenance and
  separation of duties, sourced from the NIST SP 800-171 Rev. 2 crosswalk.
  Their new mappings remain proposed pending human review.
- CMMC Level 2 awareness and role-based training mappings sourced from NIST SP
  800-171 Rev. 2 Appendix D. They raise evaluatable CMMC coverage to 96/110;
  attestable coverage is unchanged pending human review.

### Changed

- Rebuilt the README identity system around a crisp scalable hero, transparent
  wordmark, simpler four-stage operating-loop banner, and clearer navigation.
- Consolidated the queued Python and web dependency updates into one verified
  lockfile refresh.
- Mapping review output now carries validated crosswalk provenance, preferring
  the exact per-mapping locator when a safeguard is backed by multiple rows. CLI
  and MCP consumers can filter by normalized risk-domain category/family and
  receive framework/domain plus source-backed/unsourced backlog rollups.

## 0.2.6 - 2026-08-17

Release theme: **maintenance + unattended Google Workspace sync**. Closes the
last gap left by the 0.2.4 OAuth refresh work and refreshes dependencies.

### Added

- Google Workspace can be enabled with refresh-token material alone
  (`refresh_token_ref` + `client_id` + `client_secret_ref`) instead of a
  pre-minted access token. The runner already minted tokens from that triple;
  enablement validation and the console connector form previously demanded a
  static `credential_ref` anyway, so unattended sync could not be configured
  through the console. A partially-supplied triple is now rejected by name at
  probe and enable time rather than silently falling back to the static-token
  path.

### Changed

- Web console dependencies updated: `next` and `eslint-config-next` 16.3.0 ->
  16.3.1, `@xyflow/react` 12.11.2 -> 12.11.3, `@dagrejs/dagre` 3.1.0 -> 3.1.1,
  `caniuse-lite` -> 1.0.30001809, `postcss` -> 8.5.26. The console still builds
  with the pinned Webpack builder.
- Release workflow actions updated to their current majors:
  `docker/login-action` v4, `docker/metadata-action` v6,
  `softprops/action-gh-release` v3.
- The example MCP host config moved from `.cursor/mcp.json.example` to
  `examples/mcp/mcp.json.example`; it is a generic stdio MCP config, not
  editor-specific. Contents are unchanged.
- `ROADMAP.md` P7 no longer presents its issue table as open work; all nine
  linked issues are closed on GitHub, and `docs/PRODUCT_SHAPE.md` carries the
  honest per-item status (two are still _Partial_).

## 0.2.5 - 2026-08-14

Release theme: **complete the connector-resilience pass**. Closes the last gap
from the resilience audit — the append-mode readers that pulled a whole window
in one request now paginate it.

### Fixed

- ClickHouse, SIEM, and runtime-gateway readers paginate their `since`-window
  instead of truncating it at the server's first page. ClickHouse keyset-paginates
  on the composite `(event_time, event_id)` cursor with `LIMIT`, so rows sharing an
  `event_time` across a page boundary are never dropped and the loop always
  terminates. SIEM and runtime-gateway follow an optional `next_cursor` envelope
  via `?cursor=`; an export that returns a bare list is still read as a single
  page, so a non-paginating endpoint keeps working unchanged.

## 0.2.4 - 2026-08-14

Release theme: **honest framework coverage + connector resilience**. Separates
the coverage a compliance product may attest to from the coverage it merely
touches, and hardens the read-only connectors against redirects and rate limits.

### Security

- Repo-governance connector (GitHub/GitLab) now reaches its APIs through the
  same SSRF guard as every other HTTP connector, re-validating each redirect hop
  and stripping `Authorization` across origins. The GitLab base URL is
  operator-configurable, so a redirect could otherwise pivot the request and its
  bearer token at an internal address.

### Added

- Framework coverage matrix that splits **evaluatable** (any safeguard mapping)
  from **attestable** (human-reviewed — the only coverage an auditor accepts),
  surfaced via `frameworks coverage`, an MCP tool, and a committed, gated doc.
- Mapping review-queue (`frameworks review-queue`, `--framework` to scope, plus
  an MCP tool) that lists the proposed safeguard→requirement mappings awaiting
  expert sign-off, each paired with the reviewed anchors on the same safeguard.
  It never auto-promotes a mapping — accepting one stays a domain-expert call.
- Google Workspace connector supports OAuth refresh tokens for unattended sync,
  exchanging the refresh token when the access token is missing, near expiry, or
  rejected once with 401. The refresh token and client secret resolve file-first,
  and the resolved access token is held in memory only, never persisted.

### Fixed

- Connectors retry transient rate-limit / gateway errors (429/5xx, honoring
  `Retry-After`, with exponential backoff + jitter) instead of failing a whole
  sync on a single blip: SIEM, runtime-gateway, ClickHouse, and repo-governance.
  4xx stays terminal.
- Google Workspace connector follows the Directory API `nextPageToken` instead
  of a single request, so a tenant with more than a page of users/groups/members
  is no longer silently truncated.

## 0.2.3 - 2026-08-13

Release theme: **security + supply-chain currency**. Publishes the fixes and the
new connector work that landed on `main` after 0.2.2.

### Security

- Upgraded the bundled web console to Next.js 16, clearing four high-severity
  production advisories (nanoid, postcss, sharp, and the transitive next chain).
- AWS connector: `password_policy`/`console_access` now surface unexpected IAM
  errors instead of swallowing them into a false control pass.
- `required_post_scope` fails closed — a mutating route not explicitly scoped is
  denied rather than accepting the low `write` scope.

### Added

- AWS connector cloud-linking: read-only posture role, a dedicated connector
  runtime role, and the cloud-link console flow.

### Fixed

- Dropped the opaque `/api/{rest}` catch-all from the published OpenAPI spec and
  catalogued six previously undocumented served routes.
- Helm: pin the scheduler CronJob to the API pod's node when the lake PVC is
  ReadWriteOnce, so it can mount; chart version is now gated against the release.
- Corrected the `db upgrade` command in the hosted deployment guide.

### Docs

- README status badges + PyPI classifiers; architecture diagrams now use real
  vendor logos and the official Snowflake/ClickHouse marks with proportionate
  arrowheads.

## 0.2.2 - 2026-08-12

Release theme: **audit follow-through**. Applies the confirmed findings from a
four-lane audit (code / CI / product surfaces / packaging).

### Security

- Routed the Google Workspace connector client through the shared `netguard`
  guarded opener — the one credentialed client still on raw `urllib` after the
  0.2.1 egress hardening, so its OAuth bearer can no longer follow a cross-origin
  redirect.
- Stripped local-only options (`fixture_dir`) from the connector configure
  forward-merge so a value seeded off-API cannot re-attach on a later API call.
- Constant-time trust-share token comparison.

### Fixed

- AWS access keys with an unparseable `CreateDate` no longer score a false pass
  on the rotation control.
- `__version__` is derived from installed distribution metadata (no more drift).
- Helm chart version tracks the released image tag; release verification now
  gates on it.

## 0.2.1 - 2026-08-12

Release theme: **egress SSRF hardening**. Closes three confirmed server-side
request forgery findings that shared one root cause — the outbound guards
validated only the first URL, then followed redirects (and server-supplied
pagination `Link` headers) to unvalidated hosts.

### Security

- Added `netguard.open_guarded`/`open_public`: a shared HTTP opener that re-runs
  the caller's SSRF/allowlist validator on every redirect hop and drops
  `Authorization`/`Cookie` headers on any cross-origin hop.
- Routed all host-based connector clients (Okta, SIEM, ClickHouse, runtime
  gateway, Jira) through the guarded opener, closing the connector probe/discover
  SSRF and the Okta `Link`-header token-pivot.
- Reran the workflow webhook/Slack/Jira egress path through the guarded opener so
  a 302 from an allowlisted host can no longer pivot the request (or its secret
  headers, or the response body) at an internal address.

## 0.2.0 - 2026-06-29

Release theme: **invite-only hosted POC readiness**. This release turns the repo
from a local/security-lake proof into a more coherent self-hosted TrustOps
platform: deployable by URL, usable by humans, and callable by headless agents.

### Product

- Added a first-run launch surface at `/console/poc/` that checks public URL,
  human auth, headless access, source sync, trust shares, and agent review state.
- Streamlined connector onboarding so Snowflake setup starts with identity,
  discovers granted scope, then lets the operator select read objects before
  testing/enabling.
- Added connector sync proof in the drawer so operators can see latest sync
  result, evidence count, fingerprint, and timing without opening raw logs.
- Added a governed agent harness launcher in the console with sequential vs.
  LangGraph orchestration, model toggle, budget profiles, persisted runs,
  decision review, and approval-gated writes.
- Added agent review readiness to the launch flow so the hosted POC path can go:
  connect source -> sync -> assess -> run governed review -> share trust.

### Evidence, Connectors, And Ingestion

- Proved live AWS, Azure, and Snowflake ingestion paths through the same
  scenario contract used by fixtures and CI.
- Added Snowflake read-scope discovery for warehouses, databases, schemas, and
  granted views.
- Hardened continuous ingestion docs around incremental reads, idempotency,
  retry safety, scheduler operation, and customer-owned lake boundaries.
- Added pluggable sink and lake-adapter guidance for Snowflake, ClickHouse,
  DuckDB, local files, and existing evidence-lake reads.

### Agent And Workflow Runtime

- Added persisted `agent_runs` with input hashes, budget metadata, evaluation
  results, proposed decisions, approval state, and API/MCP access.
- Added optional LangGraph orchestration while keeping the deterministic
  assessment engine model-independent and usable with zero LLM configured.
- Added model budget controls for context size, fact count, and output tokens.
- Kept writes behind RBAC, allow-listed action types, idempotency, and approval.

### Security And Operations

- Hardened API error handling and CodeQL findings around path use and exception
  exposure.
- Added API pagination/rate-limit robustness and safer connector error surfaces.
- Added hosted POC, AWS + Snowflake, live cloud, and continuous ingestion
  runbooks.
- Added OIDC/SAML/API-key server-mode docs, tenant lake boundaries, redaction,
  hashes, append-only audit records, and trust-share guidance.

### Known Gaps Before Public SaaS

- No public self-serve signup, billing, SCIM lifecycle, or multi-customer
  account marketplace.
- Connector auth is POC-capable but still needs more OAuth/service-role wizards,
  secret-manager integrations, and provider-specific hosted UX polish.
- Framework packs are seeded and source-linked, but not full certification-grade
  coverage for every framework.
- Workflow automation has a usable DAG/canvas, templates, and runs, but still
  needs deeper run inspection, retries, approvals, and action logs.
- Production operations need backup/restore drills, external secret sync,
  multi-replica guidance, alerting, WAF/API gateway guidance, and hosted
  observability before a broad public launch.
