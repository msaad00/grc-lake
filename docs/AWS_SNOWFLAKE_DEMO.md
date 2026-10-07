# AWS + Snowflake Demo Package

This is the operator path for a shareable TrustOps POC: AWS hosts the console
and API, Snowflake supplies governed evidence views, and the scheduler keeps
posture fresh.

## Outcome

After this runbook, an evaluator can open one HTTPS URL, sign in, connect
Snowflake and AWS, run a sync, see posture, issue a scoped trust share, and run
an optional agent review. The same setup also supports CLI, API, MCP, and
scheduler-driven use.

## Prerequisites

- EKS cluster with AWS Load Balancer Controller, an ACM certificate covering
  `trustops-poc.example.com`, and DNS pointing to the resulting ALB.
- EBS CSI driver with an encrypted `gp3` StorageClass (or change the values).
  [EKS bootstrap](../deploy/eks-terraform/README.md) covers these prerequisites.
- Helm 3 and `kubectl` configured for the cluster.
- Snowflake bootstrap complete:
  - role: `TRUSTOPS_READER`
  - service user: `TRUSTOPS_INGEST_SVC`
  - warehouse: `TRUSTOPS_READ_WH`
  - database/schema: `TRUSTOPS_SECURITY_LAKE.EVIDENCE`
  - service key stored locally at `~/.trustops/snowflake/trustops_snowflake_key.p8`
- Optional AWS posture role from
  `deploy/aws/trustops-posture-readonly-role.yaml`.

## 1. Create Runtime Secrets

```bash
kubectl create namespace trustops --dry-run=client -o yaml | kubectl apply -f -

kubectl -n trustops create secret generic trustops-server \
  --from-literal=TRUSTOPS_COOKIE_SIGNING_KEY="$(openssl rand -hex 32)" \
  --from-literal=TRUSTOPS_SESSION_SECRET="$(openssl rand -hex 32)"

kubectl -n trustops create secret generic trustops-snowflake-key \
  --from-file=snowflake_key.p8="$HOME/.trustops/snowflake/trustops_snowflake_key.p8"
```

For OIDC, store the client secret separately:

```bash
kubectl -n trustops create secret generic trustops-oidc \
  --from-literal=client_secret="$TRUSTOPS_OIDC_CLIENT_SECRET"
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
helm upgrade --install trustops deploy/helm/trustops \
  --namespace trustops \
  --create-namespace \
  --values poc-values.yaml
```

Verify:

```bash
kubectl -n trustops get pods,cronjobs
curl -fsS https://trustops-poc.example.com/api/healthz
```

## 3. Human Flow

1. Open `https://trustops-poc.example.com/console/poc/`.
2. Confirm login, lake health, scheduler health, and connector readiness.
3. Open **Connectors**.
4. Select **Snowflake Evidence Lake**.
5. Click **Discover scope**. The server uses the mounted service key and the
   `TRUSTOPS_READER` grants to list warehouses, databases, schemas, and views.
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
curl -fsS -H "Authorization: Bearer $TRUSTOPS_API_KEY" https://trustops-poc.example.com/api/v1/connectors
curl -fsS -H "Authorization: Bearer $TRUSTOPS_API_KEY" https://trustops-poc.example.com/api/v1/posture/current
curl -fsS -H "Authorization: Bearer $TRUSTOPS_API_KEY" https://trustops-poc.example.com/api/v1/agent-runs
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
the same deterministic TrustOps core.
