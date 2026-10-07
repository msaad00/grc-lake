# Deploy

Three install surfaces — pick the one that fits your blast radius.

| Surface                      | When to use                                                                                  | Command                                                                                                                                                                                                                                          |
| ---------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Python wheel**             | Local demos, single laptop, contributor onboarding                                           | `pip install trustops-security-data-lake && security-lakehouse serve --lake build/lakehouse`                                                                                                                                                     |
| **Container image**          | CI, Docker Compose, single-host servers                                                      | `docker run -p 8787:8787 -v $PWD/build/lakehouse:/lake ghcr.io/msaad00/trustops:0.2.21`                                                                                                                                                          |
| **Helm + EKS**               | Production self-hosted, customer-data-residency requirement                                  | See [Helm chart](helm/trustops/) + [EKS reference IaC](eks-terraform/) below                                                                                                                                                                     |
| **Snowflake POC**            | Governed evidence lake using customer-owned Snowflake views                                  | Run [`snowflake/bootstrap_poc.sql`](snowflake/bootstrap_poc.sql), then connect the reader role                                                                                                                                                   |
| **Databricks POC (preview)** | Unity Catalog evidence views read by a service principal through a SQL warehouse             | Run [`databricks/bootstrap_poc.sql`](databricks/bootstrap_poc.sql), then connect the service principal                                                                                                                                           |
| **Cloud POC roles**          | Read-only AWS/Azure/GCP posture collection without static keys                               | Deploy [`aws/trustops-posture-readonly-role.yaml`](aws/trustops-posture-readonly-role.yaml), [`azure/trustops-posture-reader.bicep`](azure/trustops-posture-reader.bicep), or [`gcp/trustops-posture-reader.tf`](gcp/trustops-posture-reader.tf) |
| **AWS + Snowflake demo**     | Shareable HTTPS POC with scheduler, OIDC, Snowflake key-pair auth, and AWS read-only posture | Use [`examples/aws-snowflake-poc-values.yaml`](examples/aws-snowflake-poc-values.yaml) with the [demo package runbook](../docs/AWS_SNOWFLAKE_DEMO.md)                                                                                            |

To publish a real HTTPS link for evaluators, follow the
[shareable POC hosting runbook](../docs/SHAREABLE_POC_HOSTING.md). It combines
the chart, server auth, persistent lake storage, scheduler, and server-side
connector secrets into one operator path. For the current AWS + Snowflake
demo target, use the checked-in values profile at
[`deploy/examples/aws-snowflake-poc-values.yaml`](examples/aws-snowflake-poc-values.yaml).
Before sending the URL, run the gate in
[`docs/RELEASE_READINESS.md`](../docs/RELEASE_READINESS.md): health, auth,
source sync, posture, integrity, workflow run, agent review, trust share, and
secret-redaction checks all need to pass.

For production operations, see the
[backup and restore runbook](../docs/runbooks/BACKUP_RESTORE.md) for the lake
PVC at `/lake` and the application-state database (`server/app.db` or
`TRUSTOPS_DATABASE_URL`).

For HA deployments (read replicas + single writer), see
[HA read replicas](../docs/runbooks/HA_READ_REPLICAS.md).

Commercial hosted invites, SCIM, and billing are documented in
[COMMERCIAL_HOSTED.md](../docs/COMMERCIAL_HOSTED.md).

## Container image

The repo ships a multi-stage `Dockerfile` at the root. Build locally:

```bash
make docker-build              # builds tag trustops:dev
docker run --rm -p 8787:8787 -v $PWD/build/lakehouse:/lake trustops:dev
```

Notes:

- The image bundles the Next.js workbench (built in stage 1) inside the Python wheel (stage 2) so the runtime image has no Node dependency.
- Includes the public demo fixtures, cloud connector SDKs, and MCP entry point.
- Runs as UID 1100 (non-root) with `readOnlyRootFilesystem` compatible defaults.
- Listens on `:8787`; `/api/healthz` checks liveness and `/api/readyz` checks the application database and writable lake storage.

## Helm chart

Renders in any conformant Kubernetes ≥ 1.27:

```bash
helm install trustops ./deploy/helm/trustops \
  --namespace trustops --create-namespace \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=trustops.example.com
```

Key value groups:

- `image` — repository, tag, pull policy, pull secrets. `image.tag` defaults to the chart's `appVersion`, so the chart and image versions move together.
- `lake.persistence` — PVC backing for `gold/` + `silver/` + `bronze/` (use a CSI driver that supports `ReadWriteMany` only if you also run multiple replicas).
- `serviceAccount.annotations` — bind an IRSA role (EKS) or Workload Identity (GKE) here for read-only access to the customer evidence bucket.
- `scheduler` — opt-in CronJob that runs `security-lakehouse scheduler tick` to fire `trigger.cron` workflows. Disable with `scheduler.enabled=false` if you drive it from an external scheduler.
- `defaultTrustRole` — set to `auditor` for the Trust Center deployment so it serves the redacted projection by default.
- `security` — production guards: `requireAuthentication`, `allowInsecureNoAuth` (requires `allowInsecureOverride=acknowledged`), ingress auth enforcement, and multi-replica + RWO lake checks. See [HA read replicas](../docs/runbooks/HA_READ_REPLICAS.md).
- `extraVolumes` / `extraVolumeMounts` — mount customer-managed secrets such as
  a Snowflake service-user private key into both the API pod and scheduler
  CronJob. TrustOps should receive only a file path such as
  `SNOWFLAKE_PRIVATE_KEY_FILE=/var/run/secrets/trustops/snowflake_key.p8`.

`helm lint deploy/helm/trustops` and `helm template trustops deploy/helm/trustops` both run in CI.

## EKS reference IaC

`deploy/eks-terraform/` provisions a minimal but real EKS cluster:

- VPC with public + private subnets across 2 AZs
- EKS managed control plane + one managed node group
- OIDC provider for IRSA
- IAM role bound to the `trustops` ServiceAccount, with **read-only** access to your customer evidence S3 bucket
- Helm release of the chart with that IRSA annotation applied

```bash
cd deploy/eks-terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars               # set evidence_bucket_name
terraform init
terraform plan
terraform apply
$(terraform output -raw kubeconfig_update_command)
kubectl -n trustops get pods
```

The IAM policy is intentionally tiny: `s3:ListBucket` + `s3:GetObject*` on the named evidence bucket. No write/delete actions, no other AWS resources. That's the customer-data-residency boundary: TrustOps reads where the data lives, and the principal it runs as can't move bytes anywhere else.

## Cloud posture POC roles

The live AWS, Azure, and GCP posture connectors can be proven without static keys:

- AWS: `deploy/aws/trustops-posture-readonly-role.yaml` creates
  `TrustOpsPostureReadOnlyRole` with only the IAM read calls used by the
  connector. The trust policy is parameterized so customers can allow their own
  TrustOps runtime role, SSO role, or brokered automation principal to assume it.
  During a probe or scheduled sync, TrustOps calls STS AssumeRole with the Role
  ARN and External ID, receives short-lived session credentials, reads only the
  allowed IAM posture APIs, and lets the temporary credentials expire.
  For multiple AWS accounts, use CloudFormation StackSets or Terraform
  workspaces to roll out the same read-only role name across target accounts.
  Use one External ID per deployed role. With the default role name, TrustOps can
  confirm a target from the account ID; custom names use the Role ARN output.
  Bulk account import is the follow-up path for registering many deployed roles
  in one pass.
- Azure: `deploy/azure/trustops-posture-reader.bicep` assigns built-in `Reader`
  at subscription scope to a service principal, managed identity, or group.
  If a tenant blocks role-assignment reads, grant a customer-owned read role
  that includes `Microsoft.Authorization/roleAssignments/read`. TrustOps uses
  `DefaultAzureCredential` at runtime.
- GCP: `deploy/gcp/trustops-posture-reader.tf` creates a read-only service
  account with `iam.securityReviewer`, `cloudasset.viewer`, and
  `orgpolicy.policyViewer`, enables the read APIs, and optionally binds GKE
  Workload Identity so the runtime impersonates it with no exported key.
  TrustOps uses Application Default Credentials at runtime.

Both templates are bootstrap helpers for read-only evidence collection. They do
not create users, credentials, long-lived access keys, or remediation
permissions.

## Snowflake POC bootstrap

`deploy/snowflake/bootstrap_poc.sql` creates a minimal existing-lake proof:

- `TRUSTOPS_SECURITY_LAKE.EVIDENCE` for curated evidence views
- `TRUSTOPS_READ_WH` as an XSMALL auto-suspended read warehouse
- `TRUSTOPS_READER` with imported privileges on `SNOWFLAKE` plus USAGE/SELECT
- four secure views over `SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY`

Run it from a Snowflake role allowed to create a database, warehouse, role, and
grants. The script does not create users, stages, integrations, external
network access, or credential material. After it returns counts for the four
views, connect TrustOps with the `snowflake-evidence-lake` connector and browser
SSO for human proof, or a non-human service user with key-pair/OAuth for
continuous ingestion. See
[`docs/CONTINUOUS_INGESTION.md`](../docs/CONTINUOUS_INGESTION.md) for the
production API/scheduler contract.

## What's not in this PR

- ECR repo + image push pipeline (use `ghcr.io/msaad00/trustops` from a public release for now).
- Cross-account bucket policy examples (the IRSA role can already assume into another account if the bucket policy allows).
- GKE / AKS reference IaC — same chart works; pull-requests welcome.
