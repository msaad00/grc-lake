# Live Cloud POC

TrustOps can use live Azure, AWS, and Snowflake access for a stronger proof, but
the first POC must be read-only and reversible. Do not paste passwords,
human-scoped developer tokens, root keys, or broad cloud credentials into chat,
Git, screenshots, or PR bodies.

For repeatable end-to-end proof, use
[`security-lakehouse scenario run live-cloud-posture`](SCENARIOS.md) after the
provider-specific setup below. The scenario syncs connectors, materializes the
lake, verifies evidence integrity, freezes a snapshot, runs a workflow DAG, and
writes a JSON report.

## Credential Boundary

Preferred order:

1. local SSO or CLI profile, such as `aws sso login` or `az login`
2. short-lived assumed role or service principal scoped to read-only posture
3. service-user key-pair auth or OAuth exposed only as an environment variable
   or mounted secret for the local process

TrustOps should store configuration metadata and fingerprints, not raw cloud
secrets. Use fixtures until a live probe proves access.

## AWS Trial Account

The current AWS runner uses the standard `boto3` credential chain and only calls:

- `iam:ListUsers`
- `iam:ListMFADevices`
- `iam:ListAccessKeys`
- `iam:GetLoginProfile`
- `iam:GetAccountPasswordPolicy`
- `iam:GetAccountSummary`

Use an SSO profile or assumed read-only role. Do not create root credentials.

To create the exact read-only role TrustOps needs, deploy the CloudFormation
template in the target AWS account:

```bash
aws cloudformation deploy \
  --stack-name trustops-posture-readonly \
  --template-file deploy/aws/trustops-posture-readonly-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    TrustedPrincipalArn=arn:aws:iam::<trustops-runtime-account-id>:role/<trustops-runtime-role> \
    ExternalId=<customer-generated-external-id>
```

### AWS STS lifecycle

| Phase        | Boundary                                                                                                            |
| ------------ | ------------------------------------------------------------------------------------------------------------------- |
| Authorize    | The CloudFormation template creates the customer-owned role and trust policy with TrustOps principal + External ID. |
| Authenticate | At probe, manual sync, or scheduled sync, TrustOps calls STS AssumeRole with the Role ARN and External ID.          |
| Read         | AWS returns short-lived session credentials. TrustOps uses them only for read-only IAM posture APIs.                |
| Expire       | The temporary credentials expire after the AWS session window. The next run repeats STS AssumeRole.                 |
| Persist      | TrustOps stores connector metadata, fingerprints, and run results, not long-lived AWS access keys.                  |

For multi-account pilots, roll out the same role with **CloudFormation
StackSets** or **Terraform workspaces**. Each deployed role gets **one External
ID per deployed role**. TrustOps verifies the target with STS, then scheduled
sync assumes registered roles one at a time and tags landed evidence with the
source account before control evaluation. **Bulk account import** is the
follow-up surface for registering many rolled-out roles in one pass.

The role grants only IAM read actions needed to classify users, console access,
MFA enrollment, access-key hygiene, password policy, and account summary. Use
SSO, an assumed role, or workload identity to run the connector; do not generate
long-lived access keys.

Every connector follows **probe → configure → sync**. `configure --state enabled`
is rejected until a probe with the exact same `--credentials-json` and
`--options-json` has passed. The probe calls `sts:GetCallerIdentity` and fails
if the credentials resolve to a different account than `account_id`, then
proves `iam:ListUsers`.

**Assume-role (recommended, and required over the API/console):**

```bash
creds='{"account_id":"<account-id>","role_arn":"arn:aws:iam::<account-id>:role/TrustOpsPostureReadOnlyRole","external_id":"<external-id>"}'

security-lakehouse connectors probe --lake build/lakehouse \
  --connector-id aws-posture --credentials-json "$creds"
security-lakehouse connectors configure --lake build/lakehouse \
  --connector-id aws-posture --credentials-json "$creds" --state enabled
security-lakehouse connectors sync --lake build/lakehouse --connector-id aws-posture
```

**Local SSO or CLI profile (local CLI lake only):** omit `role_arn`, and the
CLI probe reads with the standard `boto3` credential chain (`AWS_PROFILE`, SSO,
environment). The API and console never accept this mode, so a server cannot
prove access with its own runtime identity.

```bash
aws sso login --profile trustops-poc
export AWS_PROFILE=trustops-poc
creds='{"account_id":"<account-id>"}'

security-lakehouse connectors probe --lake build/lakehouse \
  --connector-id aws-posture --credentials-json "$creds"
security-lakehouse connectors configure --lake build/lakehouse \
  --connector-id aws-posture --credentials-json "$creds" --state enabled
security-lakehouse connectors sync --lake build/lakehouse --connector-id aws-posture
```

`AWS_ACCOUNT_ID`, `AWS_ROLE_ARN`, and `AWS_EXTERNAL_ID` still override the
stored values at sync time, and sync repeats the account check. Optional
inventory services selected with `--options-json '{"services":[...]}'` that the
role cannot read land as coverage gaps (see
[Partial collection](#partial-collection-and-coverage-gaps)) instead of being
dropped silently.

Expected artifact:

```text
build/lakehouse/raw/connector_events.jsonl
```

## Azure Subscription

The Azure runner uses `DefaultAzureCredential`, so the production path is a
provider-owned identity, not a pasted password:

- hosted app + admin consent where configured
- managed identity when TrustOps runs in Azure
- federated workload identity for Kubernetes/CI
- service-principal credentials only by secret-manager reference

Local `az login` is acceptable for developer proof only. Do not present it as
the customer onboarding path. The connector reads:

- role assignments
- policy assignments
- subscription resources

For a POC, built-in `Reader` at subscription scope is usually enough for resource
and policy inventory. For many subscriptions, grant at management-group scope or
roll the same assignment across subscriptions, then import the subscription IDs.

To grant a TrustOps managed identity or Entra app read access:

```bash
subscription_id="$(az account show --query id -o tsv)"
tenant_id="$(az account show --query tenantId -o tsv)"

# Hosted app: set TRUSTOPS_AZURE_APP_ID.
# Self-hosted Azure runtime: set TRUSTOPS_AZURE_PRINCIPAL_OBJECT_ID.
trustops_app_id="${TRUSTOPS_AZURE_APP_ID:-}"
principal_object_id="${TRUSTOPS_AZURE_PRINCIPAL_OBJECT_ID:-}"

if [ -n "$trustops_app_id" ] && [ -z "$principal_object_id" ]; then
  principal_object_id="$(az ad sp show --id "$trustops_app_id" --query id -o tsv)"
fi

if [ -z "$principal_object_id" ]; then
  echo "Set TRUSTOPS_AZURE_APP_ID or TRUSTOPS_AZURE_PRINCIPAL_OBJECT_ID before running."
  exit 1
fi

az role assignment create \
  --assignee-object-id "$principal_object_id" \
  --assignee-principal-type ServicePrincipal \
  --role Reader \
  --scope "/subscriptions/$subscription_id"

printf "Tenant ID: %s\nSubscription ID: %s\n" "$tenant_id" "$subscription_id"
```

The packaged Bicep module can also assign Reader to a known app, managed
identity, or group object ID:

```bash
az deployment sub create \
  --location eastus \
  --template-file deploy/azure/trustops-posture-reader.bicep \
  --parameters principalId=<service-principal-or-managed-identity-object-id> \
               principalType=ServicePrincipal
```

If the tenant blocks role-assignment reads for that identity, grant a
customer-owned read role that includes
`Microsoft.Authorization/roleAssignments/read`.

The probe reads the subscription (`Microsoft.Resources/subscriptions/read`)
through `DefaultAzureCredential`, or the `az` CLI when the Azure SDK is not
installed, so "Test connection" proves the identity can see the subscription.

```bash
creds='{"subscription_id":"<subscription-id>"}'

security-lakehouse connectors probe --lake build/lakehouse \
  --connector-id azure-posture --credentials-json "$creds"
security-lakehouse connectors configure --lake build/lakehouse \
  --connector-id azure-posture --credentials-json "$creds" --state enabled
security-lakehouse connectors sync --lake build/lakehouse --connector-id azure-posture
```

## GCP Project

The GCP runner uses Application Default Credentials (`gcloud auth
application-default login` for a local proof; workload identity or an attached
service account in production). It reads three sub-collections:

| Sub-collection     | API                                   | Permission                              |
| ------------------ | ------------------------------------- | --------------------------------------- |
| project IAM policy | `cloudresourcemanager.googleapis.com` | `resourcemanager.projects.getIamPolicy` |
| org policies       | `orgpolicy.googleapis.com`            | `orgpolicy.policies.list`               |
| asset inventory    | `cloudasset.googleapis.com`           | `cloudasset.assets.listResource`        |

Grant the identity a read-only role that carries these permissions (for asset
inventory, Google documents `roles/cloudasset.viewer`). Enable the APIs you want
collected:

```bash
gcloud services enable orgpolicy.googleapis.com cloudasset.googleapis.com --project <project-id>
```

The probe reads the project IAM policy, the one read every sync needs:

```bash
creds='{"project_id":"<project-id>"}'

security-lakehouse connectors probe --lake build/lakehouse \
  --connector-id gcp-posture --credentials-json "$creds"
security-lakehouse connectors configure --lake build/lakehouse \
  --connector-id gcp-posture --credentials-json "$creds" --state enabled
security-lakehouse connectors sync --lake build/lakehouse --connector-id gcp-posture
```

If the Org Policy or Cloud Asset API is disabled, or the permission is denied,
the sync still lands everything readable and reports the missing piece as a
coverage gap. It fails only when no sub-collection is readable.

## Partial collection and coverage gaps

A sub-collection the provider refuses (API disabled, permission denied, optional
client library missing) becomes one `<source>.collection_gap` evidence row
instead of failing the sync. The row is an open, low-severity item with no
control mapping, so it never counts as passing or failing evidence; its
`attributes` name the `collection`, `reason` (`api_disabled`,
`permission_denied`, `client_unavailable`, `read_failed`), and the `api` or
`permission` to fix. The sync result stays `ok`; the run record adds
`metadata.partial: true` and `metadata.coverage_gaps`, and `connectors sync`
prints the same list as `coverage_gaps`. Example message:

```text
Org Policy API (orgpolicy.googleapis.com) is not enabled on project <project-id>; organization policies were not collected
```

Other provider failures (network, authentication, server errors) still fail
the sync closed. Messages that TrustOps writes itself, such as a missing
`account_id`, an account mismatch, or missing Application Default Credentials,
are shown in the run record. Raw provider text is not.

`evidence_count` on a sync is the number of distinct evidence rows landed, and
it matches the per-source count in `assessment status` evidence freshness after
materialization.

## Snowflake Evidence Lake

Snowflake is the existing-lake path. TrustOps should read curated evidence views
and never create, update, or delete source objects in the first POC.

Use these fixed POC names:

- database: `TRUSTOPS_SECURITY_LAKE`
- schema: `TRUSTOPS_SECURITY_LAKE.EVIDENCE`
- warehouse: `TRUSTOPS_READ_WH`
- read role: `TRUSTOPS_READER`
- views: `TRUSTOPS_AUDIT_EVENTS`, `TRUSTOPS_CONTROL_POSTURE`, `TRUSTOPS_ASSET_RISK`,
  `TRUSTOPS_EVIDENCE_BUNDLES`

Run [`deploy/snowflake/bootstrap_poc.sql`](../deploy/snowflake/bootstrap_poc.sql)
from a role allowed to create a database, warehouse, and role. It creates only
TrustOps-owned objects and read-only views over
`SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY`. It does not create users, passwords,
stages, integrations, or external network access.

Validate counts before connecting TrustOps:

```sql
USE ROLE TRUSTOPS_READER;
USE WAREHOUSE TRUSTOPS_READ_WH;
USE DATABASE TRUSTOPS_SECURITY_LAKE;
USE SCHEMA EVIDENCE;

SELECT COUNT(*) AS audit_events
FROM TRUSTOPS_AUDIT_EVENTS;

SELECT COUNT(*) AS control_posture
FROM TRUSTOPS_CONTROL_POSTURE;

SELECT COUNT(*) AS asset_risk
FROM TRUSTOPS_ASSET_RISK;

SELECT COUNT(*) AS evidence_bundles
FROM TRUSTOPS_EVIDENCE_BUNDLES;
```

If any validation query returns `Object does not exist, or operation cannot be
performed`, the bootstrap SQL did not run under a create-capable role, the
active user was not granted `TRUSTOPS_READER`, or one of the view grants is
missing. Rerun the bootstrap from `ACCOUNTADMIN` or an existing governed GRC
admin role that can create the database, warehouse, role, secure views, and
grants.

For a human POC, use browser SSO. No Snowflake credential needs to be pasted
into chat, Git, or TrustOps config. Do not use this path for scheduled
ingestion:

```bash
security-lakehouse connectors probe \
  --lake build/lakehouse \
  --connector-id snowflake-evidence-lake \
  --credentials-json '{"account":"'"$SNOWFLAKE_ACCOUNT"'","user":"'"$SNOWFLAKE_USER"'","credential_ref":"externalbrowser"}' \
  --options-json '{"warehouse":"TRUSTOPS_READ_WH","database":"TRUSTOPS_SECURITY_LAKE","schema":"EVIDENCE","audit_events":"TRUSTOPS_AUDIT_EVENTS","control_posture":"TRUSTOPS_CONTROL_POSTURE","asset_risk":"TRUSTOPS_ASSET_RISK","evidence_bundles":"TRUSTOPS_EVIDENCE_BUNDLES"}'
```

The probe performs lightweight `SELECT COUNT(*)` checks against every configured
view and returns sanitized per-view diagnostics. Do not enable the connector
until the probe result is `ok`.

```bash
security-lakehouse connectors configure \
  --lake build/lakehouse \
  --connector-id snowflake-evidence-lake \
  --state enabled \
  --credentials-json '{"account":"'"$SNOWFLAKE_ACCOUNT"'","user":"'"$SNOWFLAKE_USER"'","credential_ref":"externalbrowser"}' \
  --options-json '{"warehouse":"TRUSTOPS_READ_WH","database":"TRUSTOPS_SECURITY_LAKE","schema":"EVIDENCE","audit_events":"TRUSTOPS_AUDIT_EVENTS","control_posture":"TRUSTOPS_CONTROL_POSTURE","asset_risk":"TRUSTOPS_ASSET_RISK","evidence_bundles":"TRUSTOPS_EVIDENCE_BUNDLES"}'

SNOWFLAKE_ACCOUNT="$SNOWFLAKE_ACCOUNT" \
SNOWFLAKE_USER="$SNOWFLAKE_USER" \
SNOWFLAKE_AUTHENTICATOR=externalbrowser \
SNOWFLAKE_ROLE=TRUSTOPS_READER \
SNOWFLAKE_WAREHOUSE=TRUSTOPS_READ_WH \
SNOWFLAKE_DATABASE=TRUSTOPS_SECURITY_LAKE \
SNOWFLAKE_SCHEMA=EVIDENCE \
security-lakehouse connectors sync \
  --lake build/lakehouse \
  --connector-id snowflake-evidence-lake
```

For headless automation, create a non-human service user and use Snowflake
key-pair auth. The service user should have only `TRUSTOPS_READER` and
`USAGE` on `TRUSTOPS_READ_WH`.

Run [`deploy/snowflake/bootstrap_service_user.sql`](../deploy/snowflake/bootstrap_service_user.sql)
after setting `TRUSTOPS_SERVICE_RSA_PUBLIC_KEY` in the Snowflake worksheet. The
matching private key stays in your secret manager or mounted runtime secret,
not in Snowflake, Git, chat, screenshots, or TrustOps connector config.

Probe and enable the connector with a key-file reference:

```bash
security-lakehouse connectors probe \
  --lake build/lakehouse \
  --connector-id snowflake-evidence-lake \
  --credentials-json '{"account":"'"$SNOWFLAKE_ACCOUNT"'","user":"TRUSTOPS_INGEST_SVC","private_key_ref":"SNOWFLAKE_PRIVATE_KEY_FILE"}' \
  --options-json '{"warehouse":"TRUSTOPS_READ_WH","database":"TRUSTOPS_SECURITY_LAKE","schema":"EVIDENCE","role":"TRUSTOPS_READER","audit_events":"TRUSTOPS_AUDIT_EVENTS","control_posture":"TRUSTOPS_CONTROL_POSTURE","asset_risk":"TRUSTOPS_ASSET_RISK","evidence_bundles":"TRUSTOPS_EVIDENCE_BUNDLES"}'

security-lakehouse connectors configure \
  --lake build/lakehouse \
  --connector-id snowflake-evidence-lake \
  --state enabled \
  --credentials-json '{"account":"'"$SNOWFLAKE_ACCOUNT"'","user":"TRUSTOPS_INGEST_SVC","private_key_ref":"SNOWFLAKE_PRIVATE_KEY_FILE"}' \
  --options-json '{"warehouse":"TRUSTOPS_READ_WH","database":"TRUSTOPS_SECURITY_LAKE","schema":"EVIDENCE","role":"TRUSTOPS_READER","audit_events":"TRUSTOPS_AUDIT_EVENTS","control_posture":"TRUSTOPS_CONTROL_POSTURE","asset_risk":"TRUSTOPS_ASSET_RISK","evidence_bundles":"TRUSTOPS_EVIDENCE_BUNDLES"}' \
  --sync-schedule "every 15m"

SNOWFLAKE_ACCOUNT="$SNOWFLAKE_ACCOUNT" \
SNOWFLAKE_USER=TRUSTOPS_INGEST_SVC \
SNOWFLAKE_AUTHENTICATOR=SNOWFLAKE_JWT \
SNOWFLAKE_PRIVATE_KEY_FILE="$SNOWFLAKE_PRIVATE_KEY_FILE" \
SNOWFLAKE_ROLE=TRUSTOPS_READER \
SNOWFLAKE_WAREHOUSE=TRUSTOPS_READ_WH \
SNOWFLAKE_DATABASE=TRUSTOPS_SECURITY_LAKE \
SNOWFLAKE_SCHEMA=EVIDENCE \
security-lakehouse connectors sync \
  --lake build/lakehouse \
  --connector-id snowflake-evidence-lake
```

OAuth is also supported when the customer already has a governed token broker.
The token must be injected by the runtime secret manager:

```bash
security-lakehouse connectors probe \
  --lake build/lakehouse \
  --connector-id snowflake-evidence-lake \
  --credentials-json '{"account":"'"$SNOWFLAKE_ACCOUNT"'","user":"TRUSTOPS_INGEST_SVC","credential_ref":"SNOWFLAKE_OAUTH_TOKEN"}' \
  --options-json '{"warehouse":"TRUSTOPS_READ_WH","database":"TRUSTOPS_SECURITY_LAKE","schema":"EVIDENCE","audit_events":"TRUSTOPS_AUDIT_EVENTS","control_posture":"TRUSTOPS_CONTROL_POSTURE","asset_risk":"TRUSTOPS_ASSET_RISK","evidence_bundles":"TRUSTOPS_EVIDENCE_BUNDLES"}'

security-lakehouse connectors configure \
  --lake build/lakehouse \
  --connector-id snowflake-evidence-lake \
  --state enabled \
  --credentials-json '{"account":"'"$SNOWFLAKE_ACCOUNT"'","user":"TRUSTOPS_INGEST_SVC","credential_ref":"SNOWFLAKE_OAUTH_TOKEN"}' \
  --options-json '{"warehouse":"TRUSTOPS_READ_WH","database":"TRUSTOPS_SECURITY_LAKE","schema":"EVIDENCE","audit_events":"TRUSTOPS_AUDIT_EVENTS","control_posture":"TRUSTOPS_CONTROL_POSTURE","asset_risk":"TRUSTOPS_ASSET_RISK","evidence_bundles":"TRUSTOPS_EVIDENCE_BUNDLES"}'

SNOWFLAKE_ACCOUNT="$SNOWFLAKE_ACCOUNT" \
SNOWFLAKE_USER=TRUSTOPS_INGEST_SVC \
SNOWFLAKE_AUTHENTICATOR=oauth \
SNOWFLAKE_OAUTH_TOKEN="$SNOWFLAKE_OAUTH_TOKEN" \
SNOWFLAKE_ROLE=TRUSTOPS_READER \
SNOWFLAKE_WAREHOUSE=TRUSTOPS_READ_WH \
SNOWFLAKE_DATABASE=TRUSTOPS_SECURITY_LAKE \
SNOWFLAKE_SCHEMA=EVIDENCE \
security-lakehouse connectors sync \
  --lake build/lakehouse \
  --connector-id snowflake-evidence-lake
```

The default views are:

- `TRUSTOPS_AUDIT_EVENTS`
- `TRUSTOPS_CONTROL_POSTURE`
- `TRUSTOPS_ASSET_RISK`
- `TRUSTOPS_EVIDENCE_BUNDLES`

Override them only when the customer has already standardized different view
names:

```bash
SNOWFLAKE_VIEW_AUDIT_EVENTS=<view_name>
SNOWFLAKE_VIEW_CONTROL_POSTURE=<view_name>
SNOWFLAKE_VIEW_ASSET_RISK=<view_name>
SNOWFLAKE_VIEW_EVIDENCE_BUNDLES=<view_name>
```

## Remediation Boundary

Do not grant write/remediation access in the first live POC. Remediation should
be a separate opt-in executor role with:

- a different identity from read-only ingestion
- explicit human approval
- narrow allowed actions
- full audit logging
- rollback notes for each action

Until that exists, live connectors should only ingest, normalize, tag, evaluate,
snapshot, and create internal remediation tasks.
