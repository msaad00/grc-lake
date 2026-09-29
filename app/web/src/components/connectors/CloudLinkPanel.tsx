"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Building2,
  Check,
  Copy,
  ExternalLink,
  Link2,
  Loader2,
  Network,
  Plus,
  UserRound,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  useCloudLinkCompleteMutation,
  useCloudLinkStartMutation,
  useCredentialPolicy,
} from "@/lib/api/hooks";
import type { CloudLinkSession } from "@/lib/api/types";
import type { ConnectorView } from "@/lib/api/types";
import { BRAND } from "@/lib/brand";
import {
  awsRoleArnFromIdentifier,
  awsRoleIdentifierError,
  azureDelegationError,
  azureSubscriptionIdError,
  cloudLinkFieldError,
  gcpImpersonationError,
  gcpProjectIdError,
  sanitizeAzureSubscriptionId,
  sanitizeGcpProjectId,
  TENANT_PREFIX_PLACEHOLDER,
  type CredentialPolicy,
} from "@/lib/cloud-link-validation";
import {
  HOSTED_CLOUD_LINK_COPY,
  type AzureSecretKind,
} from "@/lib/console-copy";
import { getIntegrationPreset } from "@/lib/integration-presets";

const CLOUD_LINK_IDS = new Set(["aws-posture", "azure-posture", "gcp-posture"]);
const AWS_ROLE_NAME = "TrustOpsPostureReadOnlyRole";
const AWS_ROLE_NAME_ALLOWED = /[^A-Za-z0-9+=,.@_-]/g;
type AwsDeployMode = "console" | "cloudformation" | "terraform";
type AwsAccountScope = "single" | "organization" | "selected";
type AwsDeployOption = {
  value: AwsDeployMode;
  label: string;
  detail: string;
};

interface Props {
  connector: ConnectorView;
  linkSessionId?: string | null;
  onLinked: (credentials: Record<string, string>) => void;
  onToast: (msg: string) => void;
}

export function supportsCloudLink(connectorId: string) {
  return CLOUD_LINK_IDS.has(connectorId);
}

const AZURE_SECRET_KINDS = Object.keys(
  HOSTED_CLOUD_LINK_COPY.azureSecretKinds,
) as AzureSecretKind[];

function linkDescription(connectorId: string, hosted: boolean): string {
  if (hosted && connectorId === "azure-posture") {
    return HOSTED_CLOUD_LINK_COPY.azureSummary;
  }
  if (hosted && connectorId === "gcp-posture") {
    return HOSTED_CLOUD_LINK_COPY.gcpSummary;
  }
  if (connectorId === "aws-posture") {
    return "Deploy the customer-owned AWS role, then save the account target. TrustOps verifies STS assume-role after deployment.";
  }
  if (connectorId === "azure-posture") {
    return "Grant Reader to the TrustOps Entra app or workload identity, then confirm the subscription. Scheduled sync uses fresh Azure tokens; no passwords are stored.";
  }
  return "Apply the read-only Terraform reader identity in your GCP project, then enter the project ID to stage the connector.";
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}

function sanitizeAwsRoleName(value: string): string {
  return value.replace(AWS_ROLE_NAME_ALLOWED, "").slice(0, 64);
}

function awsDeploymentRoleName(roleName: string | null | undefined): string {
  return sanitizeAwsRoleName(roleName?.trim() || "") || AWS_ROLE_NAME;
}

function awsQuickCreateUrl(
  session: CloudLinkSession,
  roleName: string,
): string | null {
  if (!session.quick_create_url) return null;
  try {
    const url = new URL(session.quick_create_url);
    const selectedRoleName = awsDeploymentRoleName(roleName);
    if (url.hash.includes("?")) {
      const [path, query = ""] = url.hash.slice(1).split("?", 2);
      const params = new URLSearchParams(query);
      params.set("param_RoleName", selectedRoleName);
      url.hash = `${path}?${params.toString()}`;
    } else {
      url.searchParams.set("param_RoleName", selectedRoleName);
    }
    return url.toString();
  } catch {
    return session.quick_create_url;
  }
}

function awsDeployCommand(
  session: CloudLinkSession,
  roleName: string,
): string | null {
  if (!session.runtime_identity_ready || !session.cloudshell_command)
    return null;
  const selectedRoleName = awsDeploymentRoleName(roleName || session.role_name);
  return session.cloudshell_command.replace(
    /RoleName=[A-Za-z0-9+=,.@_-]+/,
    `RoleName=${selectedRoleName}`,
  );
}

function awsTerraformCommand(
  session: CloudLinkSession,
  roleName: string,
): string | null {
  if (
    !session.external_id ||
    !session.runtime_identity_ready ||
    !session.trusted_principal
  )
    return null;
  const trustedPrincipal = session.trusted_principal;
  const selectedRoleName = awsDeploymentRoleName(roleName || session.role_name);
  const templateSetup = session.terraform_url
    ? `terraform_dir="$(mktemp -d /tmp/trustops-posture-role.XXXXXX)"
trap 'rm -rf "$terraform_dir"' EXIT
curl -fsSL ${shellQuote(session.terraform_url)} -o "$terraform_dir/main.tf"
`
    : "";
  const manualTerraformDir = session.manual_terraform_path
    ? session.manual_terraform_path.replace(/\/[^/]+$/, "")
    : "deploy/aws";
  const terraformChdir = session.terraform_url
    ? '"$terraform_dir"'
    : shellQuote(manualTerraformDir);

  return `${templateSetup}terraform -chdir=${terraformChdir} init
terraform -chdir=${terraformChdir} apply -auto-approve \\
  -var trusted_principal_arn=${shellQuote(trustedPrincipal)} \\
  -var external_id=${shellQuote(session.external_id)} \\
  -var role_name=${shellQuote(selectedRoleName)}

terraform -chdir=${terraformChdir} output -raw role_arn`;
}

function hostedAzureCloudShellCommand(clientId: string): string {
  const appId = clientId.trim()
    ? shellQuote(clientId.trim())
    : '"${APP_CLIENT_ID:?set APP_CLIENT_ID to your app registration client ID}"';
  return `subscription_id="$(az account show --query id -o tsv)"
tenant_id="$(az account show --query tenantId -o tsv)"

# Your own app registration: hosted TrustOps authenticates as this app.
app_id=${appId}
principal_object_id="$(az ad sp show --id "$app_id" --query id -o tsv)"

az role assignment create \\
  --assignee-object-id "$principal_object_id" \\
  --assignee-principal-type ServicePrincipal \\
  --role Reader \\
  --scope "/subscriptions/$subscription_id"

printf "Tenant ID: %s\\nSubscription ID: %s\\n" "$tenant_id" "$subscription_id"`;
}

function azureCloudShellCommand(session: CloudLinkSession): string {
  const configuredAppId = session.azure_app_id
    ? shellQuote(session.azure_app_id)
    : '"${TRUSTOPS_AZURE_APP_ID:-}"';
  return `subscription_id="$(az account show --query id -o tsv)"
tenant_id="$(az account show --query tenantId -o tsv)"

# Hosted TrustOps: set TRUSTOPS_AZURE_APP_ID to the app id shown by TrustOps.
# Self-hosted in Azure: set TRUSTOPS_AZURE_PRINCIPAL_OBJECT_ID to the managed identity object id.
trustops_app_id=${configuredAppId}
principal_object_id="\${TRUSTOPS_AZURE_PRINCIPAL_OBJECT_ID:-}"

if [ -n "$trustops_app_id" ] && [ -z "$principal_object_id" ]; then
  principal_object_id="$(az ad sp show --id "$trustops_app_id" --query id -o tsv)"
fi

if [ -z "$principal_object_id" ]; then
  echo "Set TRUSTOPS_AZURE_APP_ID or TRUSTOPS_AZURE_PRINCIPAL_OBJECT_ID before running."
  exit 1
fi

az role assignment create \\
  --assignee-object-id "$principal_object_id" \\
  --assignee-principal-type ServicePrincipal \\
  --role Reader \\
  --scope "/subscriptions/$subscription_id"

printf "Tenant ID: %s\\nSubscription ID: %s\\n" "$tenant_id" "$subscription_id"`;
}

export function CloudLinkPanel({
  connector,
  linkSessionId,
  onLinked,
  onToast,
}: Props) {
  const start = useCloudLinkStartMutation();
  const complete = useCloudLinkCompleteMutation();
  const [session, setSession] = useState<CloudLinkSession | null>(null);
  const [roleArn, setRoleArn] = useState("");
  const [subscriptionId, setSubscriptionId] = useState("");
  const [projectId, setProjectId] = useState("");
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [touched, setTouched] = useState(false);
  const [awsRoleName, setAwsRoleName] = useState(AWS_ROLE_NAME);
  const [awsDeployMode, setAwsDeployMode] =
    useState<AwsDeployMode>("cloudformation");
  const [awsAccountScope, setAwsAccountScope] =
    useState<AwsAccountScope>("single");
  const [awsAccountTargets, setAwsAccountTargets] = useState<string[]>([""]);
  const [azureTenantId, setAzureTenantId] = useState("");
  const [azureClientId, setAzureClientId] = useState("");
  const [azureSecretKind, setAzureSecretKind] =
    useState<AzureSecretKind>("client_secret_ref");
  const [azureSecretRef, setAzureSecretRef] = useState("");
  const [gcpServiceAccount, setGcpServiceAccount] = useState("");
  const [delegationTouched, setDelegationTouched] = useState(false);
  const whoamiPolicy = useCredentialPolicy();
  // The session's own report wins: it is computed for this tenant at start.
  const policy: CredentialPolicy = session?.delegation
    ? {
        hosted: session.delegation.required,
        secretRefPrefix: session.delegation.secret_ref_prefix,
      }
    : whoamiPolicy;
  const hosted = policy.hosted;
  const refPrefix = policy.secretRefPrefix ?? TENANT_PREFIX_PLACEHOLDER;
  const awsRoleIdentifier = roleArn;
  const integrationPreset = getIntegrationPreset(connector.connector_id);

  useEffect(() => {
    if (!linkSessionId) return;
    setSession((prev) => {
      if (prev?.session_id === linkSessionId) return prev;
      return {
        session_id: linkSessionId,
        connector_id: connector.connector_id,
        status: "pending",
      };
    });
  }, [connector.connector_id, linkSessionId]);

  useEffect(() => {
    if (connector.connector_id !== "aws-posture" || !session?.session_id) {
      return;
    }
    setAwsRoleName(awsDeploymentRoleName(session.role_name));
  }, [connector.connector_id, session?.role_name, session?.session_id]);

  const validationError = useMemo(
    () =>
      cloudLinkFieldError(connector.connector_id, {
        roleArn: awsRoleIdentifier,
        subscriptionId,
        projectId,
      }),
    [awsRoleIdentifier, connector.connector_id, projectId, subscriptionId],
  );
  const delegationError = !hosted
    ? null
    : connector.connector_id === "azure-posture"
      ? azureDelegationError(
          {
            tenantId: azureTenantId,
            clientId: azureClientId,
            secretRef: azureSecretRef,
          },
          policy,
        )
      : connector.connector_id === "gcp-posture"
        ? gcpImpersonationError(gcpServiceAccount, policy)
        : null;
  const delegationPayload = (): Record<string, string> | undefined => {
    if (!hosted) return undefined;
    if (connector.connector_id === "azure-posture") {
      return {
        tenant_id: azureTenantId.trim(),
        client_id: azureClientId.trim(),
        [azureSecretKind]: azureSecretRef.trim(),
      };
    }
    if (connector.connector_id === "gcp-posture") {
      return { impersonate_service_account: gcpServiceAccount.trim() };
    }
    return undefined;
  };

  const canComplete =
    Boolean(session?.session_id) &&
    !complete.isPending &&
    validationError === null &&
    delegationError === null;
  const awsCloudFormationCommand = useMemo(() => {
    if (!session) return null;
    if (connector.connector_id === "aws-posture") {
      return awsDeployCommand(session, awsRoleName);
    }
    return null;
  }, [awsRoleName, connector.connector_id, session]);
  const awsTerraformDeployCommand = useMemo(() => {
    if (!session || connector.connector_id !== "aws-posture") return null;
    return awsTerraformCommand(session, awsRoleName);
  }, [awsRoleName, connector.connector_id, session]);
  const deployCommand = useMemo(() => {
    if (!session || connector.connector_id === "aws-posture") return null;
    return session.deploy_command ?? null;
  }, [connector.connector_id, session]);
  const azureDeployCommand = useMemo(() => {
    if (connector.connector_id !== "azure-posture" || !session) return null;
    return hosted
      ? hostedAzureCloudShellCommand(azureClientId)
      : azureCloudShellCommand(session);
  }, [azureClientId, connector.connector_id, hosted, session]);
  const quickCreateUrl = useMemo(() => {
    if (!session || connector.connector_id !== "aws-posture") {
      return session?.quick_create_url ?? null;
    }
    return awsQuickCreateUrl(session, awsRoleName);
  }, [awsRoleName, connector.connector_id, session]);
  const awsDeployMethod = (
    value: AwsDeployMode,
    fallbackLabel: string,
    fallbackDetail: string,
  ) => {
    const method = session?.deployment_methods?.find(
      (candidate) => candidate.id === value,
    );
    return {
      label: method?.label ?? fallbackLabel,
      detail: method?.detail ?? fallbackDetail,
    };
  };
  const awsDeployOptions: AwsDeployOption[] =
    connector.connector_id === "aws-posture"
      ? [
          quickCreateUrl
            ? {
                value: "console" as const,
                ...awsDeployMethod(
                  "console",
                  "AWS Console",
                  "Guided CloudFormation",
                ),
              }
            : null,
          awsCloudFormationCommand
            ? {
                value: "cloudformation" as const,
                ...awsDeployMethod(
                  "cloudformation",
                  "CloudFormation CLI",
                  "AWS CLI deploy",
                ),
              }
            : null,
          awsTerraformDeployCommand
            ? {
                value: "terraform" as const,
                ...awsDeployMethod(
                  "terraform",
                  "Terraform CLI",
                  "IaC workflow",
                ),
              }
            : null,
        ].filter((item): item is NonNullable<typeof item> => item !== null)
      : [];
  const effectiveAwsDeployMode = awsDeployOptions.some(
    (option) => option.value === awsDeployMode,
  )
    ? awsDeployMode
    : (awsDeployOptions[0]?.value ?? awsDeployMode);
  const activeAwsDeployCommand =
    effectiveAwsDeployMode === "terraform"
      ? awsTerraformDeployCommand
      : effectiveAwsDeployMode === "cloudformation"
        ? awsCloudFormationCommand
        : null;

  const begin = async () => {
    setFieldError(null);
    setTouched(false);
    setAwsRoleName(AWS_ROLE_NAME);
    setAwsDeployMode("cloudformation");
    setAwsAccountScope("single");
    setAwsAccountTargets([""]);
    setRoleArn("");
    try {
      const row = await start.mutateAsync({
        id: connector.connector_id,
        publicUrl:
          typeof window !== "undefined" ? window.location.origin : undefined,
      });
      setSession(row);
      onToast("Cloud link session started — complete the steps below");
    } catch (err) {
      onToast(`Cloud link failed: ${(err as Error).message}`);
    }
  };

  const resetSetup = () => {
    setSession(null);
    setRoleArn("");
    setSubscriptionId("");
    setProjectId("");
    setFieldError(null);
    setTouched(false);
    setAwsRoleName(AWS_ROLE_NAME);
    setAwsDeployMode("cloudformation");
    setAwsAccountScope("single");
    setAwsAccountTargets([""]);
    setAzureTenantId("");
    setAzureClientId("");
    setAzureSecretKind("client_secret_ref");
    setAzureSecretRef("");
    setGcpServiceAccount("");
    setDelegationTouched(false);
  };

  const finish = async () => {
    if (!session?.session_id) return;
    setTouched(true);
    setDelegationTouched(true);
    const error = cloudLinkFieldError(connector.connector_id, {
      roleArn: awsRoleIdentifier,
      subscriptionId,
      projectId,
    });
    if (error || delegationError) {
      setFieldError(error);
      onToast(error ?? delegationError ?? "");
      return;
    }
    setFieldError(null);
    try {
      const result = await complete.mutateAsync({
        id: connector.connector_id,
        sessionId: session.session_id,
        roleArn:
          connector.connector_id === "aws-posture"
            ? awsRoleArnFromIdentifier(awsRoleIdentifier, awsRoleName)
            : undefined,
        subscriptionId:
          connector.connector_id === "azure-posture"
            ? sanitizeAzureSubscriptionId(subscriptionId)
            : undefined,
        projectId:
          connector.connector_id === "gcp-posture"
            ? sanitizeGcpProjectId(projectId)
            : undefined,
        delegation: delegationPayload(),
      });
      const creds = (result.configure?.credentials ?? {}) as Record<
        string,
        string
      >;
      onLinked(creds);
      onToast("Credentials staged — run Test connection to verify access");
    } catch (err) {
      onToast(`Complete link failed: ${(err as Error).message}`);
    }
  };

  const copyDeployCommand = async (command: string | null | undefined) => {
    if (!command) return;
    try {
      await navigator.clipboard.writeText(command);
      onToast("Deploy command copied");
    } catch {
      onToast("Could not copy deploy command");
    }
  };

  const showFieldError =
    fieldError ?? (touched && validationError ? validationError : null);

  if (!supportsCloudLink(connector.connector_id)) return null;

  const isAwsPosture = connector.connector_id === "aws-posture";
  const isAzurePosture = connector.connector_id === "azure-posture";
  const headerLabel = isAwsPosture
    ? "AWS account"
    : isAzurePosture
      ? "Read-only Azure identity"
      : (integrationPreset?.title ?? "Cloud account linking");

  return (
    <section className="min-w-0 rounded-xl border border-brand/30 bg-brand/5 p-3">
      <div className="flex flex-wrap items-center gap-1.5">
        <Link2 className="h-4 w-4 text-brand" />
        <div className="text-xs font-semibold uppercase tracking-wide text-ink">
          {headerLabel}
        </div>
        <Badge tone="ready">{isAwsPosture ? "STS" : "Read-only access"}</Badge>
        {/* Azure can use a client secret; TrustOps stores only its env-var name. */}
        <Badge>
          {isAzurePosture ? "No secrets stored" : "No long-lived keys"}
        </Badge>
        {isAzurePosture && <Badge>Reader role</Badge>}
      </div>
      <p className="mt-1 max-w-3xl break-words text-xs leading-5 text-muted">
        {hosted && connector.connector_id !== "aws-posture"
          ? linkDescription(connector.connector_id, true)
          : (integrationPreset?.summary ??
            linkDescription(connector.connector_id, false))}
      </p>
      {isAwsPosture && (
        <div
          className="mt-3 grid grid-cols-2 gap-1.5 sm:grid-cols-4"
          aria-label="AWS setup progress"
        >
          {[
            "1. Choose scope",
            "2. Deploy access",
            "3. Add targets",
            "4. Verify",
          ].map((label, index) => (
            <div
              key={label}
              className={`min-w-0 rounded-md border px-2 py-1.5 text-[11px] font-semibold leading-4 ${(!session && index === 0) || (session && index === 1) ? "border-brand bg-surface text-brand" : "border-line bg-surfaceMuted text-muted"}`}
            >
              <span className="block break-words">{label}</span>
            </div>
          ))}
        </div>
      )}
      {!session ? (
        <Button
          type="button"
          variant="primary"
          size="sm"
          className="mt-2"
          onClick={begin}
          disabled={start.isPending}
        >
          {start.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Link2 className="h-4 w-4" />
          )}{" "}
          Connect cloud account
        </Button>
      ) : (
        <div className="mt-2 grid gap-2 text-sm">
          {linkSessionId && session.status === "pending" && (
            <p className="rounded-lg border border-warning/40 bg-warning-bg px-2.5 py-2 text-xs text-warning-fg">
              Returned from identity provider — confirm consent completed, then
              enter your account identifier below.
            </p>
          )}
          {connector.connector_id === "aws-posture" &&
            awsDeployOptions.length > 0 && (
              <div className="grid gap-3">
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                    1. Choose scope
                  </div>
                  <div className="mt-2 grid gap-1.5 md:grid-cols-3">
                    {[
                      {
                        value: "single" as const,
                        label: "One AWS account",
                        detail: "Best for getting started",
                        icon: UserRound,
                      },
                      {
                        value: "organization" as const,
                        label: "AWS Organization",
                        detail: "Deploy across OUs",
                        icon: Building2,
                      },
                      {
                        value: "selected" as const,
                        label: "Selected accounts",
                        detail: "Choose specific accounts",
                        icon: Network,
                      },
                    ].map((option) => {
                      const Icon = option.icon;
                      const selected = awsAccountScope === option.value;
                      return (
                        <button
                          key={option.value}
                          type="button"
                          aria-pressed={selected}
                          onClick={() => setAwsAccountScope(option.value)}
                          className={`relative min-h-24 rounded-lg border p-2.5 text-left transition ${selected ? "border-brand bg-brand/10 ring-1 ring-brand" : "border-line bg-surface hover:border-brand/50"}`}
                        >
                          {selected && (
                            <Check className="absolute right-3 top-3 h-4 w-4 text-brand" />
                          )}
                          <Icon className="h-4 w-4 text-brand" />
                          <div className="mt-1.5 pr-5 text-sm font-semibold leading-5 text-ink">
                            {option.label}
                          </div>
                          <div className="mt-0.5 text-xs leading-4 text-muted">
                            {option.detail}
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
                <div className="border-t border-line pt-2.5">
                  <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                    2. Deploy read-only access
                  </div>
                  <p className="mt-0.5 text-xs leading-4 text-muted">
                    {awsAccountScope === "organization"
                      ? "Deploy the role with CloudFormation StackSets or Terraform workspaces to the organizational units you choose."
                      : awsAccountScope === "selected"
                        ? "Run the deployment in each selected account, or customize the script for your existing IaC workflow."
                        : "Run this once in the AWS account you want TrustOps to assess."}
                  </p>
                </div>
                <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
                  <label className="grid gap-1 text-xs font-semibold uppercase tracking-wide text-muted">
                    Deployment method
                    <select
                      value={effectiveAwsDeployMode}
                      onChange={(event) =>
                        setAwsDeployMode(event.target.value as AwsDeployMode)
                      }
                      className="rounded-lg border border-line bg-surface px-3 py-2 text-sm normal-case tracking-normal text-ink focus:outline-none focus:ring-1 focus:ring-brand"
                    >
                      {awsDeployOptions.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  {effectiveAwsDeployMode === "console" && quickCreateUrl && (
                    <Button
                      type="button"
                      variant="default"
                      size="sm"
                      className="sm:mb-0"
                      onClick={() =>
                        window.open(
                          quickCreateUrl,
                          "_blank",
                          "noopener,noreferrer",
                        )
                      }
                    >
                      <ExternalLink className="h-4 w-4" />
                      Open AWS guided deploy
                    </Button>
                  )}
                </div>
                {activeAwsDeployCommand && (
                  <div className="flex flex-wrap items-center gap-2 rounded-lg border border-line bg-surface p-2">
                    <details className="text-xs text-muted">
                      <summary className="cursor-pointer list-none font-semibold text-brand">
                        View script
                      </summary>
                      <code className="mt-2 block max-h-32 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-line bg-surface px-2 py-1.5 text-[11px] font-medium text-ink">
                        {activeAwsDeployCommand}
                      </code>
                    </details>
                    <details className="text-xs text-muted">
                      <summary className="cursor-pointer list-none font-semibold text-ink">
                        Customize role
                      </summary>
                      <label className="mt-2 grid gap-1 font-semibold text-muted">
                        IAM role name
                        <input
                          value={awsRoleName}
                          onChange={(event) =>
                            setAwsRoleName(
                              sanitizeAwsRoleName(event.target.value),
                            )
                          }
                          className="rounded-lg border border-line bg-surface px-3 py-2 text-sm font-medium text-ink"
                        />
                      </label>
                    </details>
                    <Button
                      type="button"
                      variant="default"
                      size="sm"
                      className="ml-auto shrink-0"
                      onClick={() => copyDeployCommand(activeAwsDeployCommand)}
                    >
                      <Copy className="h-4 w-4" />
                      {effectiveAwsDeployMode === "cloudformation"
                        ? "Copy script"
                        : "Copy command"}
                    </Button>
                  </div>
                )}
              </div>
            )}
          {session.consent_url && (
            <Button
              type="button"
              variant="default"
              size="sm"
              onClick={() =>
                window.open(
                  session.consent_url!,
                  "_blank",
                  "noopener,noreferrer",
                )
              }
            >
              <ExternalLink className="h-4 w-4" />
              Grant Azure admin consent
            </Button>
          )}
          {connector.connector_id === "azure-posture" && azureDeployCommand && (
            <div className="rounded-lg border border-line bg-surface p-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="min-w-0">
                  <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                    Deploy Azure access
                  </div>
                </div>
                <Button
                  type="button"
                  variant="default"
                  size="sm"
                  className="shrink-0"
                  onClick={() => copyDeployCommand(azureDeployCommand)}
                >
                  <Copy className="h-4 w-4" />
                  Copy Cloud Shell setup
                </Button>
              </div>
              <details className="mt-2 text-xs text-muted">
                <summary className="cursor-pointer list-none font-semibold text-brand">
                  View command
                </summary>
                <code className="mt-2 block max-h-28 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-line bg-surface px-2 py-1.5 text-[11px] font-medium text-ink">
                  {azureDeployCommand}
                </code>
              </details>
              <details className="mt-2 text-xs text-muted">
                <summary className="cursor-pointer list-none font-semibold text-ink">
                  Scale and permissions
                </summary>
                <div className="mt-2 grid gap-1">
                  <p>
                    Use subscription scope for one account, or management-group
                    scope to cover many subscriptions.
                  </p>
                  <p>
                    Required reads: role assignments, role definitions,
                    subscriptions, policy assignments, and resources.
                  </p>
                </div>
              </details>
            </div>
          )}
          {connector.connector_id === "gcp-posture" &&
            session.template_url &&
            !deployCommand && (
              <div className="rounded-lg border border-line bg-surface p-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                      Deploy GCP access
                    </div>
                  </div>
                  <Button
                    type="button"
                    variant="default"
                    size="sm"
                    className="shrink-0"
                    onClick={() =>
                      window.open(
                        session.template_url!,
                        "_blank",
                        "noopener,noreferrer",
                      )
                    }
                  >
                    <ExternalLink className="h-4 w-4" />
                    Open Terraform template
                  </Button>
                </div>
              </div>
            )}
          {deployCommand && connector.connector_id === "gcp-posture" && (
            <div className="rounded-lg border border-line bg-surface p-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                  Deploy GCP access
                </div>
                <Button
                  type="button"
                  variant="default"
                  size="sm"
                  className="shrink-0"
                  onClick={() => copyDeployCommand(deployCommand)}
                >
                  <Copy className="h-4 w-4" />
                  Copy Terraform command
                </Button>
              </div>
              <details className="mt-2 text-xs text-muted">
                <summary className="cursor-pointer list-none font-semibold text-brand">
                  View command
                </summary>
                <code className="mt-2 block max-h-28 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-line bg-surface px-2 py-1.5 text-[11px] font-medium text-ink">
                  {deployCommand}
                </code>
              </details>
            </div>
          )}
          {connector.connector_id === "gcp-posture" &&
            !hosted &&
            !session.workload_identity_member && (
              <p className="text-xs text-muted">
                Set <code>TRUSTOPS_GCP_WIF_MEMBER</code> to include Workload
                Identity in the deploy command. Manual template:{" "}
                <code>{session.manual_template_path}</code>
              </p>
            )}
          {connector.connector_id === "aws-posture" && (
            <div className="border-t border-line pt-2.5">
              <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                3. Add account targets
              </div>
              <div className="mt-1.5 grid gap-2">
                {awsAccountTargets.map((target, index) => (
                  <label
                    key={index}
                    className="grid gap-1 text-xs font-semibold text-muted"
                  >
                    {awsAccountScope === "organization"
                      ? "Management account ID or Role ARN"
                      : awsAccountScope === "single"
                        ? "Account ID or Role ARN"
                        : `Account ${index + 1}`}
                    <input
                      value={index === 0 ? roleArn : target}
                      onChange={(event) => {
                        const value = event.target.value;
                        setAwsAccountTargets((current) =>
                          current.map((item, itemIndex) =>
                            itemIndex === index ? value : item,
                          ),
                        );
                        if (index === 0) setRoleArn(value);
                        setFieldError(null);
                      }}
                      onBlur={() => {
                        if (index === 0) {
                          setTouched(true);
                          setFieldError(
                            awsRoleIdentifierError(awsRoleIdentifier),
                          );
                        }
                      }}
                      autoComplete="off"
                      aria-invalid={index === 0 && Boolean(showFieldError)}
                      placeholder="AWS account ID or role ARN"
                      className="rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-brand"
                    />
                  </label>
                ))}
                {awsAccountScope !== "organization" && (
                  <Button
                    type="button"
                    variant="default"
                    size="sm"
                    className="justify-self-start"
                    onClick={() =>
                      setAwsAccountTargets((current) => [...current, ""])
                    }
                  >
                    <Plus className="h-4 w-4" /> Add another account
                  </Button>
                )}
              </div>
            </div>
          )}
          {connector.connector_id === "aws-posture" && (
            <details className="text-xs text-muted">
              <summary className="cursor-pointer list-none font-semibold uppercase tracking-wide text-ink">
                View permissions
              </summary>
              <div className="mt-2 grid gap-2 border-t border-line pt-2">
                <div className="grid gap-1 text-xs font-semibold uppercase tracking-wide text-muted">
                  Read-only IAM posture
                  <span
                    aria-label="IAM posture read-only"
                    className="font-semibold normal-case tracking-normal text-ink"
                    title="IAM posture read-only"
                  >
                    iam:ListUsers, iam:ListMFADevices, iam:ListAccessKeys,
                    iam:GetLoginProfile, iam:GetAccountPasswordPolicy,
                    iam:GetAccountSummary
                  </span>
                </div>
                {session.external_id && (
                  <label className="grid gap-1 font-semibold uppercase tracking-wide text-muted">
                    External ID
                    <code className="break-all rounded-lg border border-line bg-surface px-2 py-1.5 font-medium normal-case tracking-normal text-ink">
                      {session.external_id}
                    </code>
                  </label>
                )}
              </div>
            </details>
          )}
          {connector.connector_id === "azure-posture" && (
            <label className="grid gap-1 text-xs font-semibold uppercase tracking-wide text-muted">
              Azure subscription ID
              <input
                value={subscriptionId}
                onChange={(e) => {
                  setSubscriptionId(
                    sanitizeAzureSubscriptionId(e.target.value),
                  );
                  setFieldError(null);
                }}
                onBlur={() => {
                  setTouched(true);
                  setFieldError(azureSubscriptionIdError(subscriptionId));
                }}
                autoComplete="off"
                aria-invalid={Boolean(showFieldError)}
                placeholder="00000000-0000-0000-0000-000000000000"
                className="rounded-lg border border-line bg-surface px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-brand"
              />
              <span className="font-medium normal-case tracking-normal text-muted">
                Paste the subscription ID printed by setup. No Azure password or
                client secret is stored in {BRAND.name}.
              </span>
            </label>
          )}
          {connector.connector_id === "gcp-posture" && (
            <label className="grid gap-1 text-xs font-semibold uppercase tracking-wide text-muted">
              GCP project ID
              <input
                value={projectId}
                onChange={(e) => {
                  setProjectId(sanitizeGcpProjectId(e.target.value));
                  setFieldError(null);
                }}
                onBlur={() => {
                  setTouched(true);
                  setFieldError(gcpProjectIdError(projectId));
                }}
                autoComplete="off"
                aria-invalid={Boolean(showFieldError)}
                placeholder="my-gcp-project"
                className="rounded-lg border border-line bg-surface px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-brand"
              />
            </label>
          )}
          {hosted && connector.connector_id === "azure-posture" && (
            <fieldset
              aria-describedby="hosted-delegation-rule"
              className="grid gap-2 rounded-lg border border-line bg-surface p-2.5"
            >
              <legend className="px-1 text-xs font-semibold uppercase tracking-wide text-muted">
                Your Entra app registration
              </legend>
              <div className="grid gap-2 sm:grid-cols-2">
                <label className="grid min-w-0 gap-1 text-xs font-semibold text-muted">
                  Entra tenant ID
                  <input
                    value={azureTenantId}
                    onChange={(e) => setAzureTenantId(e.target.value.trim())}
                    onBlur={() => setDelegationTouched(true)}
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="00000000-0000-0000-0000-000000000000"
                    className="min-w-0 rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-brand"
                  />
                </label>
                <label className="grid min-w-0 gap-1 text-xs font-semibold text-muted">
                  Application (client) ID
                  <input
                    value={azureClientId}
                    onChange={(e) => setAzureClientId(e.target.value.trim())}
                    onBlur={() => setDelegationTouched(true)}
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="00000000-0000-0000-0000-000000000000"
                    className="min-w-0 rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-brand"
                  />
                </label>
              </div>
              <div className="grid gap-2 sm:grid-cols-[minmax(0,12rem)_minmax(0,1fr)]">
                <label className="grid min-w-0 gap-1 text-xs font-semibold text-muted">
                  Credential type
                  <select
                    value={azureSecretKind}
                    onChange={(e) =>
                      setAzureSecretKind(e.target.value as AzureSecretKind)
                    }
                    className="min-w-0 rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-brand"
                  >
                    {AZURE_SECRET_KINDS.map((kind) => (
                      <option key={kind} value={kind}>
                        {HOSTED_CLOUD_LINK_COPY.azureSecretKinds[kind].label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="grid min-w-0 gap-1 text-xs font-semibold text-muted">
                  Environment variable name
                  <input
                    value={azureSecretRef}
                    onChange={(e) => setAzureSecretRef(e.target.value.trim())}
                    onBlur={() => setDelegationTouched(true)}
                    autoComplete="off"
                    spellCheck={false}
                    placeholder={`${refPrefix}${HOSTED_CLOUD_LINK_COPY.azureSecretKinds[azureSecretKind].suffix}`}
                    className="min-w-0 rounded-lg border border-line bg-surface px-3 py-2 font-mono text-xs text-ink focus:outline-none focus:ring-1 focus:ring-brand"
                  />
                </label>
              </div>
              <p
                id="hosted-delegation-rule"
                className="break-words text-xs leading-5 text-muted"
              >
                {HOSTED_CLOUD_LINK_COPY.refRule} Names start with{" "}
                <code className="break-all rounded bg-surfaceMuted px-1 text-ink">
                  {refPrefix}
                </code>
                .
              </p>
            </fieldset>
          )}
          {hosted && connector.connector_id === "gcp-posture" && (
            <label className="grid gap-1 text-xs font-semibold uppercase tracking-wide text-muted">
              Service account to impersonate
              <input
                value={gcpServiceAccount}
                onChange={(e) => setGcpServiceAccount(e.target.value.trim())}
                onBlur={() => setDelegationTouched(true)}
                autoComplete="off"
                spellCheck={false}
                placeholder="trustops-reader@my-gcp-project.iam.gserviceaccount.com"
                className="rounded-lg border border-line bg-surface px-3 py-2 text-sm normal-case tracking-normal text-ink focus:outline-none focus:ring-1 focus:ring-brand"
              />
              <span className="font-medium normal-case tracking-normal text-muted">
                Grant the {BRAND.name} identity Service Account Token Creator on
                this account; it never reads your project as itself.
              </span>
            </label>
          )}
          {delegationTouched && delegationError && (
            <p role="alert" className="text-xs font-semibold text-danger-fg">
              {delegationError}
            </p>
          )}
          {showFieldError && (
            <p className="text-xs font-semibold text-danger-fg">
              {showFieldError}
            </p>
          )}
          <div className="flex flex-wrap items-center gap-2">
            {connector.connector_id === "aws-posture" && (
              <div className="w-full text-xs font-semibold uppercase tracking-wide text-muted">
                4. Verify and finish
              </div>
            )}
            <Button
              type="button"
              variant="default"
              size="sm"
              onClick={resetSetup}
              disabled={complete.isPending}
            >
              Back
            </Button>
            <Button
              type="button"
              variant="primary"
              size="sm"
              onClick={finish}
              disabled={!canComplete}
            >
              {complete.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Link2 className="h-4 w-4" />
              )}{" "}
              Next: verify access
            </Button>
          </div>
        </div>
      )}
    </section>
  );
}
