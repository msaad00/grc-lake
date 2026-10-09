# EKS reference deployment

This Terraform configuration provides the VPC, managed EKS cluster and node
group, namespace, read-only evidence IRSA role, and application Helm release.
It defaults to Kubernetes 1.35 and AL2023 x86-64 nodes. Check the
[AWS version lifecycle](https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html)
before choosing another version; 1.30 is no longer supported.

The creating operator receives cluster-admin access to bootstrap the cluster.
Additional access entries, restricted API endpoint access, network policies,
backup storage and production monitoring are operator-managed. EKS, EC2, NAT,
load balancers and storage incur charges when you apply this configuration.

The application still supports only one writable replica. Multiple cluster
nodes do not enable multiple GRC Lake writers or automated application failover.

## 1. Bootstrap infrastructure

Use Terraform 1.7+ and an AWS identity authorized to provision these resources.
For a new cluster, create infrastructure before asking Helm to wait for an
application whose storage and secrets do not exist yet:

```bash
cd deploy/eks-terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars
terraform init
terraform plan -var='deploy_application=false'
terraform apply -var='deploy_application=false'
aws eks update-kubeconfig --region "$(terraform output -raw region)" \
  --name "$(terraform output -raw cluster_name)"
```

`deploy_application` defaults to true to preserve existing installations.
Use false only for initial bootstrap: changing an existing installation to
false **uninstalls its Helm release**. The resource move to
`helm_release.grc-lake[0]` preserves the existing release address during upgrade;
review every plan, including any node-group replacement when changing AMI type.
For an existing cluster, pin its current `cluster_version` in `terraform.tfvars`
and follow the supported EKS minor-version upgrade sequence before adopting the
new default; do not attempt a direct multi-version jump.

## 2. Prepare cluster prerequisites

Before enabling the application:

- Install the [EBS CSI driver and its IAM permissions](https://docs.aws.amazon.com/eks/latest/userguide/ebs-csi.html).
  Provide an encrypted StorageClass using `ebs.csi.aws.com` and
  `WaitForFirstConsumer`; set `lake.persistence.storageClassName` to its name.
  The example AWS profile expects `gp3`. This stack uses managed nodes, not EKS
  Auto Mode; its storage provisioner is different from Auto Mode's.
- For ALB ingress, install the [AWS Load Balancer Controller](https://docs.aws.amazon.com/eks/latest/userguide/lbc-helm.html)
  with its own controller IAM role. Provide DNS and an ACM certificate in the
  cluster's region. ALB uses an ACM certificate ARN, not a Kubernetes TLS Secret.
- Create the runtime signing Secret in the configured namespace (default
  `grc-lake`). Keep its contents outside Terraform values/state:

```bash
kubectl -n grc-lake create secret generic grc-lake-server \
  --from-literal=GRC_LAKE_COOKIE_SIGNING_KEY="$(openssl rand -hex 32)" \
  --from-literal=GRC_LAKE_SESSION_SECRET="$(openssl rand -hex 32)"
```

`GRC_LAKE_COOKIE_SIGNING_KEY` is required for authenticated server startup.
`GRC_LAKE_SESSION_SECRET` is additionally required for OIDC. Configure OIDC/SAML
and any connector Secret references according to [server auth](../../docs/SERVER_AUTH.md).
Neither the evidence IRSA role nor the application chart installs storage or
load-balancer controllers. Those controllers require separate infrastructure
permissions; do not add them to the evidence reader role.

## 3. Configure and install the application

`server_secret_name` selects the signing Secret above. `helm_values_files`
accepts ordered, non-secret configuration files for OIDC, TLS, storage and
connector Secret references. Paths resolve from the Terraform working directory.
Helm replaces `env` lists: when providing one, retain
`GRC_LAKE_COOKIE_SIGNING_KEY`, `GRC_LAKE_ENV=production`, and, for OIDC,
`GRC_LAKE_SESSION_SECRET`. EKS enforces authenticated chart rendering after
applying all operator overrides.

For the AWS/Snowflake example, copy `../examples/aws-snowflake-poc-values.yaml`
to an operator-owned path, replace every account/host/ARN placeholder, and add
its path to `helm_values_files` in `terraform.tfvars`. Keep the Terraform-managed
`grc-lake` ServiceAccount name and use `terraform output -raw grc-lake_role_arn`
for its IRSA annotation unless you intentionally supply a separately managed role.
The example needs additional OIDC and Snowflake Secrets described in the
[AWS/Snowflake runbook](../../docs/AWS_SNOWFLAKE_DEMO.md).

The image tag defaults to the checked-out chart's `appVersion`; check out the
intended release source before installation. The chart is supplied in Git,
not published as a separate Helm OCI artifact.

```bash
terraform plan
terraform apply
kubectl -n grc-lake rollout status deployment/grc-lake
kubectl -n grc-lake get pods,pvc,cronjobs
```

Verify `/api/healthz`, `/api/readyz`, authenticated API access, human login,
source sync, scheduler results and backup/restore before sharing the URL.
See [release readiness](../../docs/RELEASE_READINESS.md). A successful Terraform
validate or mocked plan does not demonstrate a live deployment.

## Offline configuration checks

```bash
terraform init -backend=false -input=false
terraform fmt -check -recursive
terraform validate
terraform test
```

The plan-only tests mock providers and infrastructure modules. They check
bootstrap sequencing, signing Secret references, operator values, and enforced
authentication without creating resources or contacting an AWS account.
