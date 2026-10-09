const GCP_PROJECT_RE = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const AZURE_SUBSCRIPTION_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const AWS_ROLE_ARN_RE =
  /^arn:aws(?:-us-gov|-cn)?:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_\/-]{1,512}$/;

export function sanitizeAwsAccountId(raw: string): string {
  return raw.replace(/\D/g, "").slice(0, 12);
}

export function sanitizeAzureSubscriptionId(raw: string): string {
  return raw
    .replace(/[^0-9a-f-]/gi, "")
    .slice(0, 36)
    .toLowerCase();
}

export function sanitizeGcpProjectId(raw: string): string {
  return raw
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "")
    .slice(0, 30);
}

export function awsAccountIdError(raw: string): string | null {
  const digits = sanitizeAwsAccountId(raw);
  if (!digits) return "Enter your 12-digit AWS account ID.";
  if (digits.length !== 12) return "AWS account ID must be exactly 12 digits.";
  return null;
}

export function awsRoleArnError(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return "Paste the role ARN from the CloudFormation output.";
  if (!AWS_ROLE_ARN_RE.test(trimmed)) return "Use a valid AWS IAM role ARN.";
  return null;
}

export function awsRoleIdentifierError(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return "Enter your AWS account ID.";
  if (AWS_ROLE_ARN_RE.test(trimmed)) return null;
  if (trimmed.startsWith("arn:")) {
    return "Use a valid AWS IAM role ARN or a 12-digit AWS account ID.";
  }

  if (!/^[0-9\s-]+$/.test(trimmed)) {
    return "Use a valid AWS IAM role ARN or a 12-digit AWS account ID.";
  }
  const accountId = sanitizeAwsAccountId(trimmed);
  if (accountId.length !== 12) {
    return "AWS account ID must be exactly 12 digits.";
  }
  return null;
}

export function awsRoleArnFromIdentifier(
  raw: string,
  roleName: string,
): string {
  const trimmed = raw.trim();
  if (AWS_ROLE_ARN_RE.test(trimmed)) return trimmed;

  const accountId = sanitizeAwsAccountId(trimmed);
  return `arn:aws:iam::${accountId}:role/${roleName}`;
}

export function azureSubscriptionIdError(raw: string): string | null {
  const trimmed = sanitizeAzureSubscriptionId(raw);
  if (!trimmed) return "Enter your Azure subscription ID.";
  if (!AZURE_SUBSCRIPTION_RE.test(trimmed)) {
    return "Use a valid subscription GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).";
  }
  return null;
}

export function gcpProjectIdError(raw: string): string | null {
  const trimmed = sanitizeGcpProjectId(raw);
  if (!trimmed) return "Enter your GCP project ID.";
  if (!GCP_PROJECT_RE.test(trimmed)) {
    return "Use a valid GCP project ID (lowercase letters, numbers, hyphens; 6–30 chars).";
  }
  return null;
}

export function cloudLinkFieldError(
  connectorId: string,
  values: { roleArn: string; subscriptionId: string; projectId: string },
): string | null {
  if (connectorId === "aws-posture") {
    return awsRoleIdentifierError(values.roleArn);
  }
  if (connectorId === "azure-posture") {
    return azureSubscriptionIdError(values.subscriptionId);
  }
  if (connectorId === "gcp-posture") return gcpProjectIdError(values.projectId);
  return "Unsupported cloud link connector.";
}

/** The caller's connector credential policy, from whoami or a link session. */
export interface CredentialPolicy {
  hosted: boolean;
  secretRefPrefix: string | null;
}

// Mirrors security_lakehouse.secret_refs; tests/test_cloud_link_ui_contract.py
// pins these lists to the server's.
export const SERVER_SECRET_PREFIXES = [
  "GRC_LAKE_",
  "AWS_",
  "AMAZON_",
  "ECS_CONTAINER_",
  "GOOGLE_",
  "GCLOUD_",
  "CLOUDSDK_",
  "GCE_",
  "AZURE_",
  "ARM_",
  "MSI_",
  "IDENTITY_",
  "STRIPE_",
  "DATABASE_",
  "POSTGRES",
  "PG",
  "MYSQL_",
  "REDIS_",
  "SMTP_",
  "SENDGRID_",
  "KUBERNETES_",
  "KUBECONFIG",
  "VAULT_",
  "SENTRY_",
  "GITHUB_",
  "ACTIONS_",
  "SSH_",
  "OTEL_",
] as const;
export const SERVER_SECRET_NAMES = [
  "SECRET_KEY",
  "DJANGO_SECRET_KEY",
  "FLASK_SECRET_KEY",
  "HOME",
  "PATH",
] as const;

// Mirrors security_lakehouse.delegation.
const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const AZURE_TENANT_RE = /^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/;
const AZURE_CLIENT_RE =
  /^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$/;
const GCP_SERVICE_ACCOUNT_RE =
  /^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$/;

export const TENANT_PREFIX_PLACEHOLDER = "GRC_LAKE_TENANT_<ID>__";

function prefixHint(policy: CredentialPolicy): string {
  return `use the tenant prefix ${policy.secretRefPrefix ?? TENANT_PREFIX_PLACEHOLDER}`;
}

function isServerSecretName(name: string, tenantPrefix: string | null) {
  if (tenantPrefix && name.startsWith(tenantPrefix)) return false;
  const upper = name.toUpperCase();
  const base = upper.endsWith("_FILE") ? upper.slice(0, -5) : upper;
  const names: readonly string[] = SERVER_SECRET_NAMES;
  return (
    names.includes(base) ||
    names.includes(upper) ||
    SERVER_SECRET_PREFIXES.some((prefix) => upper.startsWith(prefix))
  );
}

/** An env-var reference: a name only, never the secret; hosted refuses server secrets. */
export function secretRefError(
  raw: string,
  policy: CredentialPolicy,
): string | null {
  const name = raw.trim();
  if (!name) return "Enter the environment variable that holds the secret.";
  if (!ENV_NAME_RE.test(name)) {
    return "Use an environment variable name (letters, digits, underscores); never paste the secret itself.";
  }
  if (policy.hosted && isServerSecretName(name, policy.secretRefPrefix)) {
    return `That name is reserved for server secrets in hosted mode; ${prefixHint(policy)}.`;
  }
  return null;
}

export interface AzureDelegationValues {
  tenantId: string;
  clientId: string;
  secretRef: string;
}

export function azureDelegationError(
  values: AzureDelegationValues,
  policy: CredentialPolicy,
): string | null {
  const tenantId = values.tenantId.trim();
  const clientId = values.clientId.trim();
  const secretRef = values.secretRef.trim();
  if (!policy.hosted && !tenantId && !clientId && !secretRef) return null;
  if (!AZURE_TENANT_RE.test(tenantId)) {
    return "Enter your Entra tenant ID (a GUID or verified domain).";
  }
  if (!AZURE_CLIENT_RE.test(clientId)) {
    return "Enter the app registration's client ID (the application ID GUID).";
  }
  return secretRefError(secretRef, policy);
}

export function gcpImpersonationError(
  raw: string,
  policy: CredentialPolicy,
): string | null {
  const target = raw.trim();
  if (!target) {
    return policy.hosted
      ? "Enter the service account to impersonate in your project."
      : null;
  }
  if (!GCP_SERVICE_ACCOUNT_RE.test(target)) {
    return "Use a service account email ending in .iam.gserviceaccount.com.";
  }
  return null;
}
