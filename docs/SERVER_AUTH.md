# Server Auth

TrustOps server mode has one identity model:

```text
API key, OIDC login, or SAML login
  -> user
  -> tenant
  -> role
  -> RBAC scopes
  -> request audit event
```

Local mode stays zero-dependency. These settings apply only when running the
FastAPI server surface from `trustops-security-data-lake[server]`.

Browser session cookies are **always signed**. Set a dedicated secret before
starting the server with authentication enabled:

```bash
export TRUSTOPS_COOKIE_SIGNING_KEY="$(openssl rand -hex 32)"
```

Without this key, `create_app()` fails fast when auth is required (CI, Helm, and
production deployments).

## Preferred credential model

Prefer platform workload identity or federation with scoped, short-lived access
for collectors and automation. Acquire tokens just in time; do not persist or
log token bodies, authorization headers, refresh tokens, private keys, or secrets
in evidence, screenshots, source control, or generated reports. JWTs remain
credentials and require issuer, audience, expiry, and authorization checks.

The current implementation has exceptions: TrustOps API keys can be issued without
an expiry, browser sessions need protected signing material, and the Snowflake
sink currently uses a private-key reference. These are not a fully federated,
credential-free deployment. Use explicit API-key expiry for trials and keep any
required signing material in a protected runtime secret service. Do not claim
universal credential-free operation until each integration is verified.

Platform references: [Google workload identity federation](https://docs.cloud.google.com/iam/docs/workload-identity-federation)
and [Snowflake workload identity federation](https://docs.snowflake.com/en/user-guide/workload-identity-federation).

## API Keys

API keys are for agents, CI, and service accounts. The database stores only a
derived lookup digest. Raw key material is returned once by the authenticated
API creation endpoint.

```bash
security-lakehouse platform seed-dev --lake build/lakehouse
security-lakehouse auth issue-key --lake build/lakehouse --tenant-slug dev --email admin@localhost --name local
security-lakehouse auth list-keys --lake build/lakehouse --tenant-slug acme
```

The console **Access** page (`/console/auth/`) lets admins create, list, and
revoke keys with a one-time token reveal. The CLI `auth issue-key` and
`platform seed-dev` commands deliver each new bearer token in a new owner-only (0600) file under `LAKE/server/credentials`,
and print only its `token_file` path after the database commit. Transfer the
credential to your secret manager, then remove the delivery file. Standard
output and later list commands contain metadata only. These keys authorize automation, not human attestations.

## OIDC

OIDC is the preferred human-login path when the company identity provider
supports it.

```bash
export TRUSTOPS_OIDC_ISSUER="https://idp.example.com"
export TRUSTOPS_OIDC_CLIENT_ID="trustops"
export TRUSTOPS_OIDC_CLIENT_SECRET="..."
export TRUSTOPS_OIDC_TENANT_SLUG="acme"
export TRUSTOPS_OIDC_AUTO_PROVISION="false"
export TRUSTOPS_SESSION_SECRET="replace-with-32-byte-random-secret"
export TRUSTOPS_COOKIE_SIGNING_KEY="$(openssl rand -hex 32)"
```

Endpoints:

| Endpoint                    | Purpose                                                                                       |
| --------------------------- | --------------------------------------------------------------------------------------------- |
| `GET /api/v1/auth/methods`  | Discover configured browser login methods, IdP host, setup hints, and API-key headless access |
| `GET /api/v1/auth/whoami`   | Current session user, tenant, role, and scopes                                                |
| `GET /api/v1/auth/login`    | Start OIDC login                                                                              |
| `GET /api/v1/auth/callback` | Complete OIDC login and issue the browser session                                             |
| `POST /api/v1/auth/logout`  | Revoke the browser session                                                                    |

The console **Access** page (`/console/auth/`) and sign-in page render the same
`auth.methods` payload with neutral IdP marks (Okta, Entra ID, Google, SAML) —
not official vendor logos. See [THIRD_PARTY_ASSETS.md](THIRD_PARTY_ASSETS.md).

Admins manage API keys under **Access → API keys** (create with one-time secret,
revoke, MCP config copy). Admins manage tenant users under **Access → Users &
roles** (promote, demote, deactivate). Paste an API key on the sign-in page to
open a browser session without SSO.

## User directory

| Endpoint                             | Purpose                                     |
| ------------------------------------ | ------------------------------------------- |
| `GET /api/v1/auth/users`             | List tenant users (admin)                   |
| `PATCH /api/v1/auth/users/{id}`      | Change role, active flag, or display name   |
| `POST /api/v1/auth/session-from-key` | Exchange API key for browser session cookie |

Last active admin cannot be demoted or deactivated.

## IdP group → role mapping

Map identity-provider groups to TrustOps roles on SSO login:

```bash
export TRUSTOPS_OIDC_ROLE_MAP='{"TrustOps-Admins":"admin","TrustOps-Auditors":"auditor"}'
export TRUSTOPS_OIDC_ROLE_CLAIM="groups"
export TRUSTOPS_IDP_SYNC_ROLE_ON_LOGIN="true"
```

SAML uses `TRUSTOPS_SAML_ROLE_MAP` and `TRUSTOPS_SAML_ROLE_ATTRIBUTE` (default
`groups`). When sync is enabled, each login reapplies the highest matched role.

## SCIM (commercial hosted)

Enable with commercial hosted mode plus:

```bash
export TRUSTOPS_COMMERCIAL_HOSTED="1"
export TRUSTOPS_SCIM_ENABLED="1"
export TRUSTOPS_SCIM_BEARER_TOKEN="replace-with-long-random-secret"
export TRUSTOPS_SCIM_TENANT_SLUG="acme"
```

| Endpoint                           | Purpose                   |
| ---------------------------------- | ------------------------- |
| `GET /api/v1/scim/v2/Users`        | List users                |
| `POST /api/v1/scim/v2/Users`       | Provision user            |
| `PATCH /api/v1/scim/v2/Users/{id}` | Deactivate or change role |

SCIM requests authenticate with the SCIM bearer token, not a user API key.

<p align="center">
  <img src="images/trustops-identity-boundary.svg" alt="TrustOps identity boundary: OIDC, SAML, and API keys to tenant RBAC and audit" width="100%">
</p>

Mermaid diagrams: [auth-identity.md](diagrams/auth-identity.md)

## SAML

SAML is the enterprise fallback for identity providers that do not expose OIDC
to the TrustOps deployment. It resolves into the same browser session and RBAC
context as OIDC.

```bash
export TRUSTOPS_SAML_SP_ENTITY_ID="https://trustops.example.com/api/v1/auth/saml/metadata"
export TRUSTOPS_SAML_ACS_URL="https://trustops.example.com/api/v1/auth/saml/acs"
export TRUSTOPS_SAML_IDP_ENTITY_ID="https://idp.example.com/saml"
export TRUSTOPS_SAML_IDP_SSO_URL="https://idp.example.com/saml/sso"
export TRUSTOPS_SAML_IDP_X509_CERT="-----BEGIN CERTIFICATE-----..."
export TRUSTOPS_SAML_TENANT_SLUG="acme"
export TRUSTOPS_SAML_AUTO_PROVISION="false"
```

Endpoints:

| Endpoint                         | Purpose                                                 |
| -------------------------------- | ------------------------------------------------------- |
| `GET /api/v1/auth/saml/login`    | Start SAML login                                        |
| `POST /api/v1/auth/saml/acs`     | Assertion consumer service; validates the SAML response |
| `GET /api/v1/auth/saml/metadata` | Service-provider metadata for identity-provider setup   |

If any SAML environment variable is present, all required SAML variables must
be present. The server fails closed instead of starting with a partial SSO
boundary.

Login is SP-initiated by default. `/login` stores the AuthnRequest ID in a
signed, ten-minute `SameSite=None; Secure` cookie, so the deployment must be
served over HTTPS (or `localhost`). The ACS accepts only a response whose
`InResponseTo` matches that ID. IdP-initiated (unsolicited) responses are
rejected unless `TRUSTOPS_SAML_ALLOW_IDP_INITIATED=true`. Consumed assertion
IDs are recorded in the application database (`saml_assertion_replays`, unique
on issuer + assertion ID) until their `NotOnOrAfter`, and a replay is rejected.
Replicas that share one database (`TRUSTOPS_DATABASE_URL`, as every
multi-replica deployment must) share that table, so a replay sent to a
different replica is caught too; when two replicas race on one assertion,
exactly one insert succeeds. Expired rows are swept every few minutes, and a database error
rejects the login. The table comes from migration `0020`, which the server
applies at startup.

## Roles

| Role                  | Access                                                                   |
| --------------------- | ------------------------------------------------------------------------ |
| `admin`               | Full access, including user and API key administration                   |
| `security_admin`      | Evidence requests, connectors, workflows, snapshots, and controls        |
| `compliance_reviewer` | Read, plus approve or reject safeguard mappings (`mapping_review` scope) |
| `contributor`         | Evidence request, workflow action, and triage operations                 |
| `auditor`             | Read-only, with owner, credential, and note fields redacted              |
| `read_only`           | Internal read-only view without mutation                                 |

Mapping review decisions also require a signed-in console session: an API key
used as a bearer token can read the review queue but is refused on
`POST /api/v1/mapping-reviews/decisions` whatever its role. See
[Mapping review](MAPPING_REVIEW.md).

All non-health `/api/v1/*` and `/api/*` requests are authenticated in server
mode. Request audit events include a correlation ID, actor, tenant, route,
method, decision, status, and timestamp.

## Data sensitivity defaults

TrustOps treats visibility as a server-side policy, not a UI convention.
Supported labels are `public`, `internal`, `confidential`, `restricted`, and
`secret`.

Recommended default ceilings:

| Principal             | Maximum visibility | Notes                                                                              |
| --------------------- | ------------------ | ---------------------------------------------------------------------------------- |
| `admin`               | `restricted`       | Can operate the platform; raw secrets still should not be persisted                |
| `security_admin`      | `restricted`       | Can operate evidence sources, workflows, snapshots, and controls                   |
| `compliance_reviewer` | `confidential`     | Reviews safeguard mappings; otherwise read-only                                    |
| `contributor`         | `confidential`     | Can triage and request evidence without broad admin access                         |
| `read_only`           | `confidential`     | Internal read-only posture and evidence view                                       |
| `auditor`             | `internal`         | Read-only with owner, actor, assignee, note, and credential fields redacted        |
| trust share           | `public`           | External reviewer summary only; no raw evidence, owners, notes, or asset internals |

Trust-share records include a `sensitivity_ceiling` and default to `public`.
The public trust endpoint returns a curated posture summary tagged
`sensitivity=public`, `visibility=external_reviewer`, and
`redaction_policy=trustops.public_summary.v1`. A share at the `public`
ceiling (customer trust) returns score, readiness state, and control counts
only (`detail_level=summary`); open-violation and stale-control counts are
included only for shares issued above `public`, such as an auditor review at
`internal` (`detail_level=detailed`).

## Integrity, idempotency, and API errors

Integrity defaults:

- JSON writes are atomic: readers see the old complete file or the new complete
  file, never a partial write.
- Append-only ledgers are flushed and fsync'd before an acknowledged record
  returns.
- Raw evidence rows carry SHA-256 hashes, and assessment snapshots are chained
  through `prev_hash` and `assessment_hash`.
- Raw event validation rejects duplicate `event_id` values before evaluation.

Idempotency defaults:

- Connector ingestion merges by stable source IDs so retries and overlapping
  watermarks do not duplicate evidence.
- Workflow webhooks send an `Idempotency-Key` derived from the action payload.
- Trust-share creation accepts `Idempotency-Key`; a retry with the same key
  returns the existing share metadata and does **not** mint a second external
  link. Because raw share tokens are never stored, replays do not re-expose the
  token.

API error defaults:

- `/api/v1/*` responses use `{data, meta, errors}` envelopes.
- Validation failures return `422` with `code=unprocessable_entity` and field
  detail suitable for headless agents.
- Legacy `/api/*` errors are sanitized so internal exception text is not
  returned to browsers or agents.
- Every secured request receives an `X-Correlation-ID` and an authorization
  audit event.

## Rate limiting

The authenticated API surface is rate limited per credential with an in-process
token bucket, so one caller (or a leaked key) cannot exhaust the server. The
bucket is keyed by a hash of the presented bearer token, falling back to the
client host for unauthenticated callers, so one tenant's burst never consumes
another's budget. A throttled request returns `429` with `code=rate_limited` and
a `Retry-After` header; health probes (`/api/healthz`, `/api/v1/healthz`) are
exempt so a limiter trip never hides liveness from an orchestrator.

```bash
export TRUSTOPS_API_RATE_LIMIT_RPS="50"    # steady tokens/second per credential
export TRUSTOPS_API_RATE_LIMIT_BURST="100" # bucket capacity (short-spike headroom)
```

Defaults are `50` rps / `100` burst — generous enough that interactive and agent
traffic never trips them, low enough to blunt a runaway loop. Set
`TRUSTOPS_API_RATE_LIMIT_RPS=0` to disable. The limiter is single-node and
in-process; a multi-replica deployment that needs a shared budget should front
the API with a gateway limiter or a shared store (Redis).

## Tenant data isolation

Server mode binds to a lake _root_. Each tenant's bronze/silver/gold evidence
lives under `<root>/tenants/<tenant_id>`, and every data route resolves its lake
from the authenticated identity, so one tenant can never read another tenant's
posture, controls, evidence, violations, or connector configuration.

A _flat_ lake written directly at the root — the layout the CLI `pipeline` and
`fixtures` commands produce — is served, for backward compatibility, only to a
single-tenant deployment (the sole tenant in the database) or to the synthetic
tenant of `--allow-insecure-no-auth` local mode. When a second tenant exists,
the flat root lake is bound to nobody: each tenant reads its own `tenants/<id>`
subtree (initially empty) rather than another tenant's data. Provision
per-tenant lakes by running the pipeline with `--out <root>/tenants/<tenant_id>`.

## Hosted connector credentials

In server mode a tenant admin configures connectors, and chooses both the
credential reference and the host the credential is sent to. The server
therefore never lets a tenant reach its own secrets, cloud identity, or disk.
Local and CLI runs act for the operator and are unchanged.

**Secret references.** A `*_ref` or `*_env` field (for example
`client_secret_ref`, `credential_ref`, `kubeconfig_ref`, `options.token_env`)
names an environment variable. In server mode a name resolves only when it is:

- under the tenant's own prefix `TRUSTOPS_TENANT_<TENANT_ID>__`: the tenant id
  upper-cased, `-` replaced by `_`, then a double underscore (for tenant
  `3f2b8c1e-9a4d-...`, `TRUSTOPS_TENANT_3F2B8C1E_9A4D_...__JAMF_SECRET`). Only
  lowercase alphanumeric ids with single inner hyphens (UUIDs, slugs) get a
  prefix, so no two tenants share one and no tenant's prefix starts another's;
  a tenant with any other id resolves only allowlisted names, or
- listed in `TRUSTOPS_CONNECTOR_SECRET_REFS`, a comma-separated list of exact
  names or `PREFIX*` patterns set by the operator.

Server secrets are always refused, whatever the allowlist says: every
`TRUSTOPS_*` name other than the tenant's own prefix, and names starting with
`AWS_`, `GOOGLE_`, `GCLOUD_`, `CLOUDSDK_`, `AZURE_`, `ARM_`, `STRIPE_`,
`DATABASE_`, `POSTGRES`, `PG`, `REDIS_`, `SMTP_`, `KUBERNETES_`, `KUBECONFIG`,
`VAULT_`, `GITHUB_`, and similar (the full list is `DENIED_PREFIXES` in
`src/security_lakehouse/secret_refs.py`). The same decision covers the
`<NAME>_FILE` mounted-secret variant. A disallowed reference is rejected when the
connector is configured or probed, and again at sync for configs saved earlier.
A connector's built-in default variable (for example `JAMF_CLIENT_SECRET` when no
ref is set) is the operator's global credential and follows the same rule, so
hosted tenants must set an explicit ref.

**Delegated cloud access.** The server never collects with its own identity:

- AWS readers (`aws-posture`, `object-storage-evidence`, Iceberg on Glue, Parquet
  on S3) require the tenant's `role_arn` and `external_id`. The server-wide
  `AWS_ROLE_ARN` and `AWS_EXTERNAL_ID` overrides are ignored for tenants.
- GCP readers (`gcp-posture`, `bigquery-evidence-lake`) require
  `impersonate_service_account`: a service account in the customer's project
  that grants the TrustOps runtime identity `roles/iam.serviceAccountTokenCreator`.
  The server's Application Default Credentials only mint that impersonated
  token. GCP has no external-id equivalent, so run each hosted deployment's
  runtime under a service account that customers grant only to TrustOps.
- BigQuery refuses a fully qualified source table in another project than the
  configured `project_id` unless `options.allow_cross_project` is true.
- Kubernetes requires `kubeconfig_ref` naming the tenant's kubeconfig; the
  in-cluster service account and the server's `KUBECONFIG` are refused.
- Azure readers (`azure-posture`, `intune-devices`) authenticate as the
  customer's own Entra app registration: `tenant_id`, `client_id`, and exactly
  one of `client_secret_ref` (the app's client secret),
  `client_certificate_ref` (a PEM certificate with its private key, inline or
  mounted via `<NAME>_FILE`), or `federated_token_file_ref` (a path to a
  workload identity token that the app's federated credential trusts). Each
  reference follows the secret-reference rule above, so it names a
  `TRUSTOPS_TENANT_<TENANT_ID>__` variable the operator provisions for that
  tenant. `DefaultAzureCredential` and the `az` CLI login are refused, and the
  server-wide `AZURE_SUBSCRIPTION_ID` and `AZURE_TENANT_ID` overrides are
  ignored for tenants. Grant the app `Reader` on the subscription
  (`azure-posture`) or the Graph application permission
  `DeviceManagementManagedDevices.Read.All` with admin consent (`intune-devices`).
- Snowflake refuses an inline `private_key_file` path and `externalbrowser` auth.

The console's one-click cloud link collects these fields in server mode. A
`POST /api/v1/connectors/{id}/link/start` session reports
`delegation: {required, secret_ref_prefix}`, and `GET /api/v1/auth/whoami`
reports the same as `hosted` and `secret_ref_prefix`, so forms show the
tenant's prefix in placeholders and hints. `link/complete` takes a
`delegation` object: `tenant_id`, `client_id`, and one secret reference for
`azure-posture`, or `impersonate_service_account` for `gcp-posture`. It is
validated with the readers' rules before anything is staged. References are
env-var names only; a value that is not a variable name is refused, so a
pasted secret is never stored. In server mode the link offers no admin-consent
URL for an operator-owned multi-tenant app (`TRUSTOPS_AZURE_LINK_CLIENT_ID`),
because tenants never collect through it. The consent callback is
unauthenticated, so the Entra tenant it reports is kept on the link session for
display only and is never written into a connector config.

**Workflow secrets.** A workflow action's `{{secret.NAME}}` token resolves
locally from `TRUSTOPS_SECRET_<NAME>`. In server mode it resolves from the
calling tenant's `TRUSTOPS_TENANT_<TENANT_ID>__SECRET_<NAME>` (for tenant
`acme`, `{{secret.SLACK_WEBHOOK}}` reads `TRUSTOPS_TENANT_ACME__SECRET_SLACK_WEBHOOK`).
The token names only the suffix, so a tenant can never reach another tenant's
variable. The shared `TRUSTOPS_SECRET_<NAME>` is used in server mode only for
names the operator lists in `TRUSTOPS_WORKFLOW_SHARED_SECRETS`
(comma-separated, for example `STATUSPAGE_TOKEN`), and only when the tenant has
no variable of its own with that name. Any other name fails the action, and
nothing is sent.

**Local lake paths.** `TRUSTOPS_LAKE_LOCAL_ROOT` is shared by the whole server,
so a hosted tenant may read local Parquet only under
`$TRUSTOPS_LAKE_LOCAL_ROOT/<tenant_id>`.

A request is in server mode when the FastAPI server (`serve --server`) handles it. A
process with `TRUSTOPS_COMMERCIAL_HOSTED=1` applies the same policy to runs
without a request, such as a scheduler pass over `<root>/tenants/<tenant_id>`,
and takes the tenant from that lake path.

The bundled console redirects unauthenticated browser traffic to `/console/login`.
That page reads `GET /api/v1/auth/methods` and only enables login buttons for
configured OIDC or SAML providers. Agent and CI access should continue to use
API keys.

## Human review boundaries

Exception approvals, remediation verification, access-review decisions, policy
acknowledgments, and workflow approval/rejection require an OIDC or SAML session
in addition to the existing role scope. API keys and cookies exchanged from keys
cannot perform these actions. Policy acknowledgment records the signed-in
employee only; admins cannot attest on another employee's behalf.

Remediation creators and assigned owners cannot verify their own tasks. Hosted
workflow initiators cannot approve their own run. Access certification rejects a
reviewer whose email matches the item's subject ID or subject name; opaque
provider subject identifiers still require an independently assigned reviewer.
Linked remediation tasks must use the evidence retest endpoint instead of being
resolved or dismissed through a status edit. Unauthenticated local serving is
forbidden in production and staging, including with the insecure override.

## Review authority and interrupted claims

Access-review decisions require an active campaign and a named human reviewer.
Completed and cancelled campaigns are immutable; completing a campaign requires
at least one item and no pending decisions. A recorded item decision cannot be
reset. Begin a new campaign for a later review.

Separation of duties resolves tenant-owned email, user ID, and SCIM external-ID
bindings, including `mailto:` email aliases. Provider identifiers such as ARNs
must be bound through the identity directory; display-name guesses do not prove
ownership. Remediation retests retain creators and all recorded owners across
reassignment. Migration 0026 preserves existing tasks but leaves their unknown
historical authority unset; those tasks require a new task and independent
retest rather than manufactured ownership history.

Queued operations retain the authorizing session ID and revalidate that session
at execution. Revoked or expired sessions cannot execute queued work. Jobs from
older versions without session provenance fail closed.

An independent SSO reviewer with `workflow_manage` can close an interrupted
workflow approval claim using `POST /api/v1/workflows/runs/{run_id}/reconcile`
with a nonempty `note`. Inspect provider receipts first. Recovery records
`interrupted` and `outcome_unknown`; it never reruns actions or asserts success.
It refuses a live worker and blocks retry of the reconciled run. If further work
is necessary, explicitly start a new workflow run after checking its side effects.

Downgrade refuses to discard retained remediation review receipts, exception
approval identity, or task/job authority provenance. Restore an independently
verified backup to use an older application; do not erase audit evidence to make
a schema downgrade succeed. Empty installations still support migration reversal.
