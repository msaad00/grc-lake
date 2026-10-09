# Shareable POC Hosting

This is the shortest path from a local GRC Lake proof to a link a team can
open, sign into, connect a source, and evaluate posture.

```text
https://grc-lake.example.com
  -> GRC Lake API + console
  -> authenticated users and API keys
  -> tenant lake at /lake
  -> server-side connector secrets
  -> scheduler-driven syncs
  -> trust-center links for external reviewers
```

## What You Are Publishing

Publish the GRC Lake console and API, not a raw evidence store.

| Surface                | Who uses it                 | Authentication             | Data shown                                      |
| ---------------------- | --------------------------- | -------------------------- | ----------------------------------------------- |
| `/console/*`           | Security, GRC, auditors     | OIDC/SAML session          | Tenant-scoped posture, controls, evidence, work |
| `/api/v1/*`            | Agents, CLI, integrations   | API key or browser session | Same tenant-scoped resources as the UI          |
| `/console/trust/<tok>` | Customers and reviewers     | Scoped share token         | Public/redacted trust summary only              |
| `/api/public/trust/*`  | External trust-center embed | Scoped share token         | Public/redacted trust summary only              |

Do not publish:

- raw Snowflake private keys, OAuth tokens, cloud keys, or PATs;
- direct access to `/lake`;
- unauthenticated connector setup;
- administrator API keys in browser-visible config.

## Recommended POC Architecture

| Layer         | POC default                                             | Production hardening                                           |
| ------------- | ------------------------------------------------------- | -------------------------------------------------------------- |
| Runtime       | Helm chart on EKS, AKS, GKE, or a small managed cluster | Private nodes, workload identity, external secrets             |
| URL           | Public HTTPS ingress, e.g. `grc-lake-poc.example.com`   | WAF/API gateway, managed cert rotation, private admin routes   |
| Auth          | One tenant, OIDC/SAML for humans, API keys for agents   | SCIM/user lifecycle, least-privilege roles, enforced SSO       |
| State         | Persistent volume mounted at `/lake`                    | Backup policy, encrypted volume, tenant-specific lake prefixes |
| Evidence      | Read-only Snowflake/cloud/service identities            | Customer IaC owns roles, grants, views, and secret rotation    |
| Scheduler     | Helm CronJob every 5 minutes                            | Dedicated scheduler plus alerting on failed connector runs     |
| Trust sharing | Token-scoped trust-center links                         | Expiry, revocation, sensitivity ceilings, audit review         |

## 1. Build Or Use The Image

For a public POC, use the version pinned in your checked-out release chart;
record the image digest for reproducibility:

```bash
GRC_LAKE_VERSION=$(awk '/^appVersion:/ {gsub(/"/, "", $2); print $2}' deploy/helm/grc-lake/Chart.yaml)
docker pull "ghcr.io/msaad00/grc-lake:$GRC_LAKE_VERSION"
```

For a private build:

```bash
make docker-build
docker tag grc-lake:dev registry.example.com/grc-lake:2026-06-poc
docker push registry.example.com/grc-lake:2026-06-poc
```

The image serves both the FastAPI backend and the built React console from the
same process. The public app URL is therefore the API URL too.

## 2. Create Runtime Secrets

Create secrets in the hosting platform. GRC Lake should receive references or
mounted files, not raw values typed into the UI.

```bash
kubectl create namespace grc-lake --dry-run=client -o yaml | kubectl apply -f -
```

Minimum server secrets:

```bash
kubectl -n grc-lake create secret generic grc-lake-server \
  --from-literal=GRC_LAKE_COOKIE_SIGNING_KEY="$(openssl rand -hex 32)" \
  --from-literal=GRC_LAKE_SESSION_SECRET="$(openssl rand -hex 32)"
```

Snowflake key-pair example:

```bash
kubectl -n grc-lake create secret generic grc-lake-snowflake-key \
  --from-file=snowflake_key.p8="$HOME/.grc-lake/snowflake/grc-lake_snowflake_key.p8"
```

For AWS/Azure/GCP, prefer workload identity or assumed roles over exported
static keys:

- AWS: IRSA/EKS service account role, or a customer-owned role the runtime can
  assume.
- Azure: managed identity or federated workload identity.
- GCP: Workload Identity or a service account mounted by the platform.

## 3. Deploy With Helm

For a generic deployment, create a POC values file. For an AWS +
Snowflake POC, start from the checked-in profile instead:

```bash
cp deploy/examples/aws-snowflake-poc-values.yaml poc-values.yaml
$EDITOR poc-values.yaml
```

That profile includes the scheduler, OIDC placeholders, Snowflake key-pair
mount, and EKS IRSA annotation. The minimal shape is:

```yaml
# poc-values.yaml
image:
  repository: ghcr.io/msaad00/grc-lake
  tag: "" # inherit appVersion from the checked-out release chart

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: grc-lake-poc.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: grc-lake-poc-tls
      hosts:
        - grc-lake-poc.example.com

lake:
  persistence:
    enabled: true
    size: 20Gi

scheduler:
  enabled: true
  schedule: "*/5 * * * *"

security:
  requireAuthentication: true

env:
  - name: GRC_LAKE_ENV
    value: production
  - name: GRC_LAKE_COOKIE_SIGNING_KEY
    valueFrom:
      secretKeyRef:
        name: grc-lake-server
        key: GRC_LAKE_COOKIE_SIGNING_KEY
  - name: GRC_LAKE_SESSION_SECRET
    valueFrom:
      secretKeyRef:
        name: grc-lake-server
        key: GRC_LAKE_SESSION_SECRET
  - name: GRC_LAKE_PUBLIC_URL
    value: https://grc-lake-poc.example.com
  - name: SNOWFLAKE_PRIVATE_KEY_FILE
    value: /var/run/secrets/grc-lake/snowflake_key.p8

extraVolumeMounts:
  - name: snowflake-key
    mountPath: /var/run/secrets/grc-lake
    readOnly: true

extraVolumes:
  - name: snowflake-key
    secret:
      secretName: grc-lake-snowflake-key
```

Install:

```bash
helm upgrade --install grc-lake deploy/helm/grc-lake \
  --namespace grc-lake \
  --create-namespace \
  --values poc-values.yaml
```

Verify:

```bash
kubectl -n grc-lake get pods
curl -fsS https://grc-lake-poc.example.com/api/healthz
```

## 4. Turn On Server Auth

For a shareable link, do not use `--allow-insecure-no-auth`.

Configure OIDC before sharing the URL. Merge these settings with the existing
`env` entries; Helm replaces lists rather than appending them. Preserve both
signing Secret references:

```yaml
security:
  requireAuthentication: true

env:
  - name: GRC_LAKE_ENV
    value: production
  - name: GRC_LAKE_COOKIE_SIGNING_KEY
    valueFrom:
      secretKeyRef:
        name: grc-lake-server
        key: GRC_LAKE_COOKIE_SIGNING_KEY
  - name: GRC_LAKE_SESSION_SECRET
    valueFrom:
      secretKeyRef:
        name: grc-lake-server
        key: GRC_LAKE_SESSION_SECRET
  - name: GRC_LAKE_PUBLIC_URL
    value: https://grc-lake-poc.example.com
  - name: GRC_LAKE_OIDC_ISSUER
    value: https://idp.example.com
  - name: GRC_LAKE_OIDC_CLIENT_ID
    value: grc-lake-poc
  - name: GRC_LAKE_OIDC_CLIENT_SECRET
    valueFrom:
      secretKeyRef:
        name: grc-lake-oidc
        key: client_secret
  - name: GRC_LAKE_OIDC_TENANT_SLUG
    value: poc
  - name: GRC_LAKE_OIDC_AUTO_PROVISION
    value: "true"
```

Use API keys for headless clients and agents. API keys are stored hashed in the
server database and should be scoped to the minimum role needed.

## 5. Connect Sources From The UI

After login:

1. Open `/console/connectors/`.
2. Pick Snowflake, AWS, Azure, or GCP.
3. Enter the non-secret account identifier and service identity name.
4. Use **Discover scope** to list granted objects or cloud accounts.
5. Select the scope from dropdowns.
6. Run **Test connection**.
7. Enable the connector.
8. Click **Sync now** or wait for the scheduler.

This is the human flow. The API, CLI, scheduler, and agent harness use the same
backend connector contract.

## 6. Share Trust Without Sharing Raw Evidence

Use the Trust Center page to issue a scoped external share. The share link is
for reviewers and customers, not operators.

Recommended defaults:

- expiry: 1 to 7 days for a POC;
- sensitivity ceiling: `public`;
- no raw evidence, credentials, owners, assignees, or notes;
- revoke after the review.

## 7. POC Readiness Checklist

Before sending the link, confirm:

- `GET /api/healthz` returns ok over HTTPS.
- Browser login works through OIDC/SAML.
- At least one admin user and one read-only/auditor user exist.
- `/console/poc/` shows no blocking setup item.
- One connector has an `ok` probe and one successful sync.
- `/console/dashboard/` shows fresh evidence and current posture.
- `/console/trust-center/` can create and revoke a share.
- Scheduler CronJob has a recent successful run.
- No raw credential values appear in connector config, run history, logs, or UI.

The canonical release gate lives in
[Release Readiness](RELEASE_READINESS.md). Use it before tagging a release or
sharing an evaluator URL: it covers the same POC checks plus build, Helm,
integrity, workflow, and agent-review verification.

## Current Gaps

The repository supplies a self-hosted POC path. A running deployment still needs
the readiness checks above. A public multi-customer
SaaS-style launch still needs:

- external secret-manager integration beyond mounted Kubernetes secrets;
- polished first-run tenant/user bootstrap;
- operator qualification of the gated hosted invites, SCIM and billing features;
- distributed writer fencing and read-replica support before considering HA;
- managed backups and restore drills for `/lake`;
- deeper hosted observability around connector failures and scheduler lag.

Those are hosting/platform gaps, not assessment-engine gaps: the core evidence,
evaluation, snapshots, connector runs, workflow runs, and agent harness already
use one deterministic lake-backed contract.
