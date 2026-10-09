# Deploy

Install locally, on a single host, or in your Kubernetes cluster. Cloud evidence
roles and warehouse bootstrap scripts are connector setup, not application hosting.

| Surface                      | When to use                                                                                  | Command                                                                                                                                                                                                                                          |
| ---------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Python wheel**             | Local demos, single laptop, contributor onboarding                                           | See [Python and MCP installation](../docs/DEPLOYMENT.md#python-and-mcp)                                                                                                                                                                          |
| **Container image**          | CI, Docker Compose, single-host servers                                                      | `docker compose up -d grc-lake-server` (configure `grc-lake.env` first)                                                                                                                                                                          |
| **Helm + EKS**               | Production self-hosted, customer-data-residency requirement                                  | See [Helm chart](helm/grc-lake/) + [EKS reference IaC](eks-terraform/) below                                                                                                                                                                     |
| **Snowflake POC**            | Governed evidence lake using customer-owned Snowflake views                                  | Run [`snowflake/bootstrap_poc.sql`](snowflake/bootstrap_poc.sql), then connect the reader role                                                                                                                                                   |
| **Databricks POC (preview)** | Unity Catalog evidence views read by a service principal through a SQL warehouse             | Run [`databricks/bootstrap_poc.sql`](databricks/bootstrap_poc.sql), then connect the service principal                                                                                                                                           |
| **Cloud POC roles**          | Read-only AWS/Azure/GCP posture collection without static keys                               | Deploy [`aws/grc-lake-posture-readonly-role.yaml`](aws/grc-lake-posture-readonly-role.yaml), [`azure/grc-lake-posture-reader.bicep`](azure/grc-lake-posture-reader.bicep), or [`gcp/grc-lake-posture-reader.tf`](gcp/grc-lake-posture-reader.tf) |
| **AWS + Snowflake demo**     | Shareable HTTPS POC with scheduler, OIDC, Snowflake key-pair auth, and AWS read-only posture | Use [`examples/aws-snowflake-poc-values.yaml`](examples/aws-snowflake-poc-values.yaml) with the [demo package runbook](../docs/AWS_SNOWFLAKE_DEMO.md)                                                                                            |

To publish a real HTTPS link for evaluators, follow the
[shareable POC hosting runbook](../docs/SHAREABLE_POC_HOSTING.md). It combines
the chart, server auth, persistent lake storage, scheduler, and server-side
connector secrets into one operator path. For an AWS + Snowflake
POC example, use the checked-in values profile at
[`deploy/examples/aws-snowflake-poc-values.yaml`](examples/aws-snowflake-poc-values.yaml).
Before sending the URL, run the gate in
[`docs/RELEASE_READINESS.md`](../docs/RELEASE_READINESS.md): health, auth,
source sync, posture, integrity, workflow run, agent review, trust share, and
secret-redaction checks all need to pass.

For production operations, see the
[backup and restore runbook](../docs/runbooks/BACKUP_RESTORE.md) for the lake
PVC at `/lake` and the application-state database (`server/app.db` or
`GRC_LAKE_DATABASE_URL`).

Local mode uses **one writable application replica**, with one scheduler owner
per lake; updates use `Recreate` and have downtime. Opt-in
[distributed mode](../docs/DISTRIBUTED.md) runs multiple API, reader and worker
replicas using PostgreSQL and S3 with private scratch volumes. See the
[topology and recovery boundary](../docs/runbooks/HA_READ_REPLICAS.md).

Commercial hosted invites, SCIM, and billing are documented in
[COMMERCIAL_HOSTED.md](../docs/COMMERCIAL_HOSTED.md).

## Container image

The repo ships a multi-stage `Dockerfile`; `make docker-build` creates a local
`grc-lake:dev` image. To run the published release with authentication:

```bash
cp deploy/compose/grc-lake.env.example grc-lake.env
chmod 600 grc-lake.env
$EDITOR grc-lake.env            # signing key, public URL, optional OIDC
# Use the release pinned by compose.yaml:
docker compose up -d grc-lake-server
```

Notes:

- The image bundles the Next.js workbench (built in stage 1) inside the Python wheel (stage 2) so the runtime image has no Node dependency.
- Includes the public demo fixtures, cloud connector SDKs, and MCP entry point.
- Runs as UID 1100 (non-root) with `readOnlyRootFilesystem` compatible defaults.
- Listens on `:8787`; `/api/healthz` checks liveness and `/api/readyz` checks the application database and writable lake storage.

## Helm chart

The chart declares Kubernetes ≥ 1.27 syntax compatibility. Use a Kubernetes
version still supported by your provider; this minimum is not a support-lifecycle
claim. The chart is checked into the release source; the release workflow
publishes the container, not a separate Helm repository or OCI chart.

Create the signing Secret, then install the authenticated profile. Configure
OIDC/SAML, ingress/TLS and the storage class for your cluster before sharing it:

```bash
kubectl create namespace grc-lake --dry-run=client -o yaml | kubectl apply -f -
kubectl -n grc-lake create secret generic grc-lake-server \
  --from-literal=GRC_LAKE_COOKIE_SIGNING_KEY="$(openssl rand -hex 32)"
helm upgrade --install grc-lake ./deploy/helm/grc-lake \
  --namespace grc-lake \
  --values deploy/examples/self-hosted-values.yaml
```

Key value groups:

- `image` — repository, tag, pull policy, pull secrets. `image.tag` defaults to the chart's `appVersion`, so the chart and image versions move together.
- `lake.persistence` — PVC backing for `gold/` + `silver/` + `bronze/` (a working CSI driver and StorageClass are operator prerequisites; RWX does not enable multiple replicas).
- `serviceAccount.annotations` — bind an IRSA role (EKS) or Workload Identity (GKE) here for read-only access to the customer evidence bucket.
- `scheduler` — enabled-by-default CronJob that runs `grc-lake scheduler tick` to fire `trigger.cron` workflows. Disable with `scheduler.enabled=false` if you drive it from an external scheduler.
- `defaultTrustRole` — set to `auditor` for the Trust Center deployment so it serves the redacted projection by default.
- `security` — production guards: `requireAuthentication`, `allowInsecureNoAuth` (requires `allowInsecureOverride=acknowledged`), ingress auth enforcement, and rejection of every replica count except one and every read-only lake. See [topology limits](../docs/runbooks/HA_READ_REPLICAS.md).
- `extraVolumes` / `extraVolumeMounts` — mount customer-managed secrets such as
  a Snowflake service-user private key into both the API pod and scheduler
  CronJob. GRC Lake should receive only a file path such as
  `SNOWFLAKE_PRIVATE_KEY_FILE=/var/run/secrets/grc-lake/snowflake_key.p8`.

`helm lint deploy/helm/grc-lake` and `helm template grc-lake deploy/helm/grc-lake` both run in CI.

## EKS reference IaC

`deploy/eks-terraform/` defines a VPC, managed EKS control plane and node group,
IRSA read-only evidence role, namespace, and optional Helm release. The default
Kubernetes version is 1.35 with AL2023 x86-64 nodes. Follow the
[EKS bootstrap runbook](eks-terraform/README.md) to prepare storage, controller,
TLS and Secret prerequisites before enabling the application. Terraform accepts
operator Helm values through `helm_values_files`; no secret bytes belong there.

The evidence IAM policy grants S3 list/read operations on the named bucket(s).
It does not enforce network egress or prevent separately configured connectors
and sinks from exporting data. Cross-account access needs a bucket policy that
grants this role access; the template does not grant `sts:AssumeRole`.

## Cloud posture POC roles

The live AWS, Azure, and GCP posture connectors can be proven without static keys:

- AWS: `deploy/aws/grc-lake-posture-readonly-role.yaml` creates
  `GrcLakePostureReadOnlyRole` with only the IAM read calls used by the
  connector. The trust policy is parameterized so customers can allow their own
  GRC Lake runtime role, SSO role, or brokered automation principal to assume it.
  During a probe or scheduled sync, GRC Lake calls STS AssumeRole with the Role
  ARN and External ID, receives short-lived session credentials, reads only the
  allowed IAM posture APIs, and lets the temporary credentials expire.
  For multiple AWS accounts, use CloudFormation StackSets or Terraform
  workspaces to roll out the same read-only role name across target accounts.
  Use one External ID per deployed role. With the default role name, GRC Lake can
  confirm a target from the account ID; custom names use the Role ARN output.
  Bulk account import is the follow-up path for registering many deployed roles
  in one pass.
- Azure: `deploy/azure/grc-lake-posture-reader.bicep` assigns built-in `Reader`
  at subscription scope to a service principal, managed identity, or group.
  If a tenant blocks role-assignment reads, grant a customer-owned read role
  that includes `Microsoft.Authorization/roleAssignments/read`. GRC Lake uses
  `DefaultAzureCredential` at runtime.
- GCP: `deploy/gcp/grc-lake-posture-reader.tf` creates a read-only service
  account with `iam.securityReviewer`, `cloudasset.viewer`, and
  `orgpolicy.policyViewer`, enables the read APIs, and optionally binds GKE
  Workload Identity so the runtime impersonates it with no exported key.
  GRC Lake uses Application Default Credentials at runtime.

These templates are bootstrap helpers for read-only evidence collection. They do
not create users, credentials, long-lived access keys, or remediation
permissions.

## Snowflake POC bootstrap

`deploy/snowflake/bootstrap_poc.sql` creates a minimal existing-lake proof:

- `GRC_LAKE_SECURITY_LAKE.EVIDENCE` for curated evidence views
- `GRC_LAKE_READ_WH` as an XSMALL auto-suspended read warehouse
- `GRC_LAKE_READER` with imported privileges on `SNOWFLAKE` plus USAGE/SELECT
- four secure views over `SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY`

Run it from a Snowflake role allowed to create a database, warehouse, role, and
grants. The script does not create users, stages, integrations, external
network access, or credential material. After it returns counts for the four
views, connect GRC Lake with the `snowflake-evidence-lake` connector and browser
SSO for human proof, or a non-human service user with key-pair/OAuth for
continuous ingestion. See
[`docs/CONTINUOUS_INGESTION.md`](../docs/CONTINUOUS_INGESTION.md) for the
production API/scheduler contract.

## Infrastructure not supplied here

- ECR repo + image push pipeline (use `ghcr.io/msaad00/grc-lake` from a public release for now).
- Cross-account bucket policies or additional role-assumption permissions.
- GKE / AKS reference IaC — same chart works; pull-requests welcome.
