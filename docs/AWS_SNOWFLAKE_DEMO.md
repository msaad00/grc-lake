# AWS + Snowflake Demo Package

This is the operator path for a shareable GRC Lake POC: AWS hosts the console
and API, Snowflake supplies governed evidence views, and the scheduler keeps
posture fresh.

## Outcome

After this runbook, an evaluator can open one HTTPS URL, sign in, connect
Snowflake and AWS, run a sync, see posture, issue a scoped trust share, and run
an optional agent review. The same setup also supports CLI, API, MCP, and
scheduler-driven use.

## Prerequisites

- EKS cluster with AWS Load Balancer Controller, an ACM certificate covering
  `grc-lake-poc.example.com`, and DNS pointing to the resulting ALB.
- EBS CSI driver with an encrypted `gp3` StorageClass (or change the values).
  [EKS bootstrap](../deploy/eks-terraform/README.md) covers these prerequisites.
- Helm 3 and `kubectl` configured for the cluster.
- Snowflake bootstrap complete:
  - role: `GRC_LAKE_READER`
  - service user: `GRC_LAKE_INGEST_SVC`
  - warehouse: `GRC_LAKE_READ_WH`
  - database/schema: `GRC_LAKE_SECURITY_LAKE.EVIDENCE`
  - service key stored locally at `~/.grc-lake/snowflake/grc-lake_snowflake_key.p8`
- Optional AWS posture role from
  `deploy/aws/grc-lake-posture-readonly-role.yaml`.

## 1. Create Runtime Secrets

```bash
kubectl create namespace grc-lake --dry-run=client -o yaml | kubectl apply -f -

kubectl -n grc-lake create secret generic grc-lake-server \
  --from-literal=GRC_LAKE_COOKIE_SIGNING_KEY="$(openssl rand -hex 32)" \
  --from-literal=GRC_LAKE_SESSION_SECRET="$(openssl rand -hex 32)"

kubectl -n grc-lake create secret generic grc-lake-snowflake-key \
  --from-file=snowflake_key.p8="$HOME/.grc-lake/snowflake/grc-lake_snowflake_key.p8"
```

For OIDC, store the client secret separately:

```bash
kubectl -n grc-lake create secret generic grc-lake-oidc \
  --from-literal=client_secret="$GRC_LAKE_OIDC_CLIENT_SECRET"
```

Use External Secrets Operator, AWS Secrets Manager, or another secret manager
for longer-lived environments. Kubernetes secrets are enough for a controlled
POC but should not become the permanent source of record.

## 2. Deploy

Copy the example values and set the host, ACM certificate ARN, Snowflake account, OIDC issuer,
and IRSA role ARN:

```bash
cp deploy/examples/aws-snowflake-poc-values.yaml poc-values.yaml
$EDITOR poc-values.yaml
```

Install or upgrade:

```bash
helm upgrade --install grc-lake deploy/helm/grc-lake \
  --namespace grc-lake \
  --create-namespace \
  --values poc-values.yaml
```

Verify:

```bash
kubectl -n grc-lake get pods,cronjobs
curl -fsS https://grc-lake-poc.example.com/api/healthz
```

## 3. Human Flow

1. Open `https://grc-lake-poc.example.com/console/poc/`.
2. Confirm login, lake health, scheduler health, and connector readiness.
3. Open **Connectors**.
4. Select **Snowflake Evidence Lake**.
5. Click **Discover scope**. The server uses the mounted service key and the
   `GRC_LAKE_READER` grants to list warehouses, databases, schemas, and views.
6. Select the views that represent audit events, control posture, asset risk,
   and evidence bundles.
7. Click **Test connection**, then **Enable connector**, then **Sync now**.
8. Repeat for AWS posture using an assumed read-only role, not static keys.
9. Open **Dashboard** to review posture, **Evidence** to inspect hashes and
   freshness, and **Trust center** to issue a scoped share.

## 4. Headless And Agent Flow

The UI, CLI, API, scheduler, and agent harness all use the same lake-backed
contracts:

```bash
curl -fsS -H "Authorization: Bearer $GRC_LAKE_API_KEY" https://grc-lake-poc.example.com/api/v1/connectors
curl -fsS -H "Authorization: Bearer $GRC_LAKE_API_KEY" https://grc-lake-poc.example.com/api/v1/posture/current
curl -fsS -H "Authorization: Bearer $GRC_LAKE_API_KEY" https://grc-lake-poc.example.com/api/v1/agent-runs
```

Optional LangGraph runs are advisory. They can read redacted posture and propose
approval-gated actions, but they cannot rewrite evidence, controls, verdicts,
snapshots, or audit logs.

## 5. Readiness Gate

Before sharing the link externally:

- public HTTPS works and redirects unauthenticated users to OIDC;
- Snowflake probe and sync have one `ok` run;
- AWS posture probe and sync have one `ok` run, if enabled;
- scheduler has a recent successful tick;
- dashboard shows fresh evidence and a non-empty framework portfolio;
- trust-center share can be issued, viewed, expired, and revoked;
- connector logs show fingerprints and error classes, not raw secrets;
- no raw keys, passwords, PATs, or OAuth tokens appear in config, logs, or UI.

## Production Delta

For a real customer pilot, add external secret sync, backup/restore for `/lake`,
WAF or API gateway controls, OIDC group-to-role mapping, connector-failure
alerts, and a written data-retention policy. Those are hosting controls around
the same deterministic GRC Lake core.
