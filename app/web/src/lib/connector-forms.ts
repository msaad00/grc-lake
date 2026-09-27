/** Connection and scope field definitions for the connector drawer. */

export interface ConnectorFieldDef {
  name: string;
  label: string;
  placeholder: string;
  secret?: boolean;
  required?: boolean;
  hint?: string;
}

export const CONNECTOR_CREDENTIAL_FIELDS: Record<string, ConnectorFieldDef[]> =
  {
    "clickhouse-telemetry-lake": [
      {
        name: "host",
        label: "ClickHouse host",
        placeholder: "https://cluster.example.clickhouse.cloud:8443",
        required: true,
      },
      {
        name: "user",
        label: "Read-only user",
        placeholder: "trustops_reader",
      },
      {
        name: "credential_ref",
        label: "Scoped credential reference",
        placeholder: "TRUSTOPS_CLICKHOUSE_TOKEN",
        required: true,
        hint: "Environment variable name holding the read-only token.",
      },
    ],
    "iceberg-parquet-lake": [
      {
        name: "catalog_type",
        label: "Source type",
        placeholder: "glue",
        required: true,
        hint: "glue (AWS Glue, including Amazon Security Lake), rest (Iceberg REST catalog), or parquet.",
      },
      {
        name: "region",
        label: "AWS region",
        placeholder: "us-east-1",
        hint: "Required for Glue; used for S3 Parquet reads.",
      },
      {
        name: "role_arn",
        label: "Read-only role ARN (optional)",
        placeholder: "arn:aws:iam::111122223333:role/trustops-lake-reader",
        hint: "Assumed for Glue and S3 reads; otherwise the runtime's AWS identity is used.",
      },
      {
        name: "external_id",
        label: "External ID (optional)",
        placeholder: "trustops-external-id",
      },
      {
        name: "uri",
        label: "REST catalog URI",
        placeholder: "https://catalog.example.com/api/catalog",
        hint: "REST catalogs only; must be HTTPS on a public address.",
      },
      {
        name: "warehouse",
        label: "REST warehouse",
        placeholder: "security_lake",
      },
      {
        name: "credential_ref",
        label: "Bearer token env var",
        placeholder: "TRUSTOPS_ICEBERG_TOKEN",
        hint: "REST catalogs only; a short-lived token supplied by your secret broker.",
      },
      {
        name: "path",
        label: "Parquet location",
        placeholder: "s3://aws-security-data-lake-us-east-1-abc/aws/SH_FINDINGS/1.0/",
        hint: "Parquet only: s3://bucket/prefix, or a local path under TRUSTOPS_LAKE_LOCAL_ROOT.",
      },
    ],
    "snowflake-evidence-lake": [
      {
        name: "account",
        label: "Snowflake account",
        placeholder: "MJFAYEE-YS65534",
        required: true,
      },
      {
        name: "user",
        label: "Service user",
        placeholder: "TRUSTOPS_INGEST_SVC",
        required: true,
      },
      {
        name: "private_key_ref",
        label: "Credential reference",
        placeholder: "SNOWFLAKE_PRIVATE_KEY_FILE",
        required: true,
        hint: "Runtime secret reference for key-pair or OAuth; do not paste a key or password.",
      },
      {
        name: "role",
        label: "Read-only role (optional)",
        placeholder: "TRUSTOPS_READER",
      },
      {
        name: "private_key_file_pwd_ref",
        label: "Key password env var (optional)",
        placeholder: "SNOWFLAKE_PRIVATE_KEY_FILE_PWD",
      },
    ],
    "aws-posture": [
      {
        name: "account_id",
        label: "AWS account ID",
        placeholder: "123456789012",
        required: true,
      },
      {
        name: "role_arn",
        label: "Read-only role ARN (optional)",
        placeholder:
          "arn:aws:iam::123456789012:role/TrustOpsPostureReadOnlyRole",
        hint: "Cross-account assume-role; pair with external ID in the trust policy.",
      },
      {
        name: "external_id",
        label: "External ID (optional, with role ARN)",
        placeholder: "shared secret used in the role trust policy",
      },
    ],
    "azure-posture": [
      {
        name: "subscription_id",
        label: "Azure subscription ID",
        placeholder: "00000000-0000-0000-0000-000000000000",
        required: true,
        hint: "Confirm the subscription after granting Reader to the TrustOps app or workload identity.",
      },
    ],
    "intune-devices": [
      {
        name: "tenant_id",
        label: "Microsoft Entra tenant ID",
        placeholder: "00000000-0000-0000-0000-000000000000",
        required: true,
        hint: "Tenant whose Intune devices TrustOps reads. The TrustOps app or managed identity needs the Graph application permission DeviceManagementManagedDevices.Read.All.",
      },
    ],
    "bamboohr-personnel": [
      {
        name: "company_domain",
        label: "BambooHR company domain",
        placeholder: "acme",
        required: true,
        hint: "The subdomain only: acme for acme.bamboohr.com.",
      },
      {
        name: "credential_ref",
        label: "API key env var",
        placeholder: "BAMBOOHR_API_KEY",
        required: true,
        hint: "API key of a dedicated BambooHR user whose access level can view only the employment fields TrustOps reads.",
      },
    ],
    "rippling-personnel": [
      {
        name: "credential_ref",
        label: "API token env var",
        placeholder: "RIPPLING_API_TOKEN",
        required: true,
        hint: "Rippling API token limited to the workers.read scope.",
      },
    ],
    "jamf-devices": [
      {
        name: "base_url",
        label: "Jamf Pro URL",
        placeholder: "https://yourcompany.jamfcloud.com",
        required: true,
        hint: "Bare https URL of the Jamf Pro server, without a path.",
      },
      {
        name: "client_id",
        label: "API client ID",
        placeholder: "00000000-0000-0000-0000-000000000000",
        required: true,
        hint: "Jamf Pro API client whose API role grants only Read Computers and Read Mobile Devices.",
      },
      {
        name: "client_secret_ref",
        label: "Client secret env var",
        placeholder: "JAMF_CLIENT_SECRET",
        required: true,
        hint: "API client secret, stored as a secret reference. TrustOps mints short-lived tokens from it.",
      },
      {
        name: "screen_lock_attribute",
        label: "Mac screen-lock extension attribute",
        placeholder: "Screen Lock Enforced",
        hint: "Optional. Computer extension attribute reporting true/false for screen-lock enforcement; Macs are not evaluated for screen lock without it.",
      },
    ],
    "crowdstrike-falcon": [
      {
        name: "cloud",
        label: "Falcon cloud",
        placeholder: "us-1",
        required: true,
        hint: "us-1, us-2, eu-1, us-gov-1, or us-gov-2.",
      },
      {
        name: "client_id",
        label: "API client ID",
        placeholder: "0123456789abcdef0123456789abcdef",
        required: true,
        hint: "Falcon API client with only the Hosts, Prevention policies, and Alerts read scopes.",
      },
      {
        name: "client_secret_ref",
        label: "Client secret env var",
        placeholder: "CROWDSTRIKE_CLIENT_SECRET",
        required: true,
        hint: "API client secret, stored as a secret reference. TrustOps mints short-lived tokens from it.",
      },
    ],
    "kubernetes-cluster": [
      {
        name: "cluster_name",
        label: "Cluster name",
        placeholder: "prod-eks",
        required: true,
        hint: "Label used for evidence and asset IDs.",
      },
      {
        name: "context",
        label: "Kubeconfig context",
        placeholder: "prod-eks-readonly",
        hint: "Optional. Leave empty to use the current context, or when TrustOps runs in-cluster.",
      },
      {
        name: "kubeconfig_ref",
        label: "Kubeconfig path env var",
        placeholder: "KUBECONFIG",
        hint: "Optional. Environment variable holding the kubeconfig path for the read-only identity; defaults to KUBECONFIG or the in-cluster service account.",
      },
      {
        name: "allowed_registries",
        label: "Allowed image registries",
        placeholder:
          "123456789012.dkr.ecr.us-east-1.amazonaws.com, registry.k8s.io",
        hint: "Optional, comma-separated. Without it, image sources are recorded as inventory only.",
      },
    ],
    "knowbe4-training": [
      {
        name: "region",
        label: "KnowBe4 account region",
        placeholder: "us",
        required: true,
        hint: "us, eu, ca, uk, or de — the server your console is on (training.knowbe4.com is us).",
      },
      {
        name: "credential_ref",
        label: "Reporting API key env var",
        placeholder: "KNOWBE4_API_TOKEN",
        required: true,
        hint: "Key from the KnowBe4 Reporting API console (read-only reporting), stored as a secret reference.",
      },
    ],
    "workday-personnel": [
      {
        name: "report_url",
        label: "RaaS report URL",
        placeholder:
          "https://wd5-services1.myworkday.com/ccx/service/customreport2/<tenant>/<owner>/<report>?format=json",
        required: true,
        hint: "JSON URL of the custom report with the TrustOps column contract (see docs/CONNECTORS.md).",
      },
      {
        name: "username",
        label: "Integration system user",
        placeholder: "isu_trustops",
        required: true,
      },
      {
        name: "credential_ref",
        label: "ISU password env var",
        placeholder: "WORKDAY_ISU_PASSWORD",
        required: true,
      },
    ],
    "databricks-evidence-lake": [
      {
        name: "host",
        label: "Workspace host",
        placeholder: "dbc-a1b2345c-d6e7.cloud.databricks.com",
        required: true,
        hint: "Bare workspace hostname (AWS, Azure, or GCP Databricks).",
      },
      {
        name: "warehouse_id",
        label: "SQL warehouse ID",
        placeholder: "1234567890abcdef",
        required: true,
      },
      {
        name: "catalog",
        label: "Evidence catalog",
        placeholder: "trustops",
        required: true,
      },
      {
        name: "schema",
        label: "Evidence schema",
        placeholder: "evidence",
        required: true,
      },
      {
        name: "client_id",
        label: "Service principal application ID",
        placeholder: "00000000-0000-0000-0000-000000000000",
        required: true,
      },
      {
        name: "client_secret_ref",
        label: "OAuth secret env var",
        placeholder: "DATABRICKS_CLIENT_SECRET",
        required: true,
        hint: "Service principal OAuth secret, stored as a secret reference. TrustOps mints one-hour tokens from it.",
      },
    ],
    "gcp-posture": [
      {
        name: "project_id",
        label: "GCP project ID",
        placeholder: "my-project-123456",
        required: true,
        hint: "Uses Application Default Credentials (WIF or service account).",
      },
    ],
    "github-security": [
      {
        name: "credential_ref",
        label: "GitHub App installation token env",
        placeholder: "TRUSTOPS_GITHUB_APP_INSTALLATION_TOKEN",
        required: true,
        hint: "Read-only GitHub App token with repository metadata scopes.",
      },
    ],
    "gitlab-security": [
      {
        name: "credential_ref",
        label: "GitLab access token env",
        placeholder: "TRUSTOPS_GITLAB_ACCESS_TOKEN",
        required: true,
        hint: "Read-only project token with api read_repository scope.",
      },
    ],
    "okta-identity": [
      {
        name: "org_url",
        label: "Okta org URL",
        placeholder: "https://your-org.okta.com",
        required: true,
      },
      {
        name: "credential_ref",
        label: "API token env var",
        placeholder: "OKTA_API_TOKEN",
        required: true,
        hint: "Read-only Okta API token (okta.users.read, okta.policies.read).",
      },
    ],
    "okta-system-log": [
      {
        name: "org_url",
        label: "Okta org URL",
        placeholder: "https://your-org.okta.com",
        required: true,
      },
      {
        name: "credential_ref",
        label: "API token env var",
        placeholder: "OKTA_API_TOKEN",
        required: true,
      },
    ],
    "google-workspace-identity": [
      {
        name: "customer_id",
        label: "Google Workspace customer ID",
        placeholder: "C01234567",
        required: true,
      },
      {
        name: "credential_ref",
        label: "OAuth access token env",
        placeholder: "GOOGLE_WORKSPACE_ACCESS_TOKEN",
        hint: "Read-only directory scopes; token mounted by your secret manager. Supply this or the three unattended-refresh fields below.",
      },
      {
        name: "refresh_token_ref",
        label: "Refresh token env (unattended)",
        placeholder: "GOOGLE_WORKSPACE_REFRESH_TOKEN",
        hint: "Set all three refresh fields to run without a pre-minted access token. A _FILE variant of this name is preferred when both are present.",
      },
      {
        name: "client_id",
        label: "OAuth client ID (unattended)",
        placeholder: "1234567890-abc.apps.googleusercontent.com",
      },
      {
        name: "client_secret_ref",
        label: "OAuth client secret env (unattended)",
        placeholder: "GOOGLE_WORKSPACE_OAUTH_CLIENT_SECRET",
      },
    ],
    "jira-ticketing": [
      {
        name: "base_url",
        label: "Jira site URL",
        placeholder: "https://your-org.atlassian.net",
        required: true,
      },
      {
        name: "email",
        label: "Jira account email",
        placeholder: "grc-bot@your-org.com",
        required: true,
      },
      {
        name: "credential_ref",
        label: "API token env var",
        placeholder: "JIRA_API_TOKEN",
        required: true,
        hint: "Read-only Jira Cloud API token for the service account.",
      },
    ],
    "object-storage-evidence": [
      {
        name: "role_arn",
        label: "Read-only role ARN (optional)",
        placeholder:
          "arn:aws:iam::123456789012:role/TrustOpsEvidenceReadOnlyRole",
        hint: "Cross-account assume-role; ambient IAM works when omitted.",
      },
      {
        name: "external_id",
        label: "External ID (optional, with role ARN)",
        placeholder: "shared secret used in the role trust policy",
      },
    ],
    "siem-alerts": [
      {
        name: "host",
        label: "SIEM export URL",
        placeholder: "https://siem.example.com",
        required: true,
      },
      {
        name: "credential_ref",
        label: "Scoped credential reference",
        placeholder: "TRUSTOPS_SIEM_TOKEN",
        required: true,
        hint: "Environment variable name holding the read-only export token.",
      },
    ],
    "runtime-gateway": [
      {
        name: "host",
        label: "Runtime gateway URL",
        placeholder: "https://runtime.example.com",
        required: true,
      },
      {
        name: "credential_ref",
        label: "Scoped credential reference",
        placeholder: "TRUSTOPS_RUNTIME_GATEWAY_TOKEN",
        required: true,
        hint: "Environment variable name holding the read-only export token.",
      },
    ],
  };

export const CONNECTOR_SCOPE_FIELDS: Record<string, ConnectorFieldDef[]> = {
  "aws-posture": [
    {
      name: "region",
      label: "Region",
      placeholder: "us-east-1",
    },
    {
      name: "regions",
      label: "Inventory regions",
      placeholder: "us-east-1, us-west-2",
      hint: "Comma-separated regions scanned on each sync.",
    },
    {
      name: "services",
      label: "Inventory services",
      placeholder:
        "ec2, s3, rds, cloudtrail, config, securityhub, organizations",
      hint: "Choose only the read-only inventory surfaces you need.",
    },
  ],
  "github-security": [
    {
      name: "repo",
      label: "Repository (owner/name)",
      placeholder: "acme-corp/platform",
      required: true,
      hint: "Single repo per connector; add another connector row for more repos.",
    },
  ],
  "gitlab-security": [
    {
      name: "repo",
      label: "Project path (group/project)",
      placeholder: "acme/platform",
      required: true,
      hint: "GitLab project path; URL-encode nested groups if needed.",
    },
    {
      name: "api_url",
      label: "GitLab API URL (optional)",
      placeholder: "https://gitlab.com/api/v4",
      hint: "Self-managed GitLab base API URL; defaults to gitlab.com.",
    },
  ],
  "iceberg-parquet-lake": [
    {
      name: "security_lake_sources",
      label: "Security Lake sources (Glue)",
      placeholder: "cloud_trail_mgmt, sh_findings",
      hint: "Used when no mapping is configured; each source maps through the OCSF presets.",
    },
    {
      name: "initial_window_days",
      label: "First-sync window (days)",
      placeholder: "30",
      hint: "The first sync reads this many recent days; later syncs continue from the watermark.",
    },
  ],
  "snowflake-evidence-lake": [
    {
      name: "warehouse",
      label: "Warehouse",
      placeholder: "TRUSTOPS_READ_WH",
      required: true,
    },
    {
      name: "database",
      label: "Database",
      placeholder: "TRUSTOPS_SECURITY_LAKE",
      required: true,
    },
    {
      name: "schema",
      label: "Schema",
      placeholder: "EVIDENCE",
      required: true,
    },
    {
      name: "audit_events",
      label: "Audit events view",
      placeholder: "TRUSTOPS_AUDIT_EVENTS",
      required: true,
    },
    {
      name: "control_posture",
      label: "Control posture view",
      placeholder: "TRUSTOPS_CONTROL_POSTURE",
      required: true,
    },
    {
      name: "asset_risk",
      label: "Asset risk view",
      placeholder: "TRUSTOPS_ASSET_RISK",
      required: true,
    },
    {
      name: "evidence_bundles",
      label: "Evidence bundles view",
      placeholder: "TRUSTOPS_EVIDENCE_BUNDLES",
      required: true,
    },
  ],
  "object-storage-evidence": [
    {
      name: "bucket",
      label: "S3 bucket",
      placeholder: "trustops-evidence",
      required: true,
    },
    {
      name: "prefix",
      label: "Evidence prefix",
      placeholder: "bundles/",
      required: true,
      hint: "LIST/GET scope; trailing slash recommended.",
    },
    {
      name: "region",
      label: "Region (optional)",
      placeholder: "us-east-1",
    },
  ],
  "siem-alerts": [
    {
      name: "index",
      label: "Alert index",
      placeholder: "alerts",
      required: true,
      hint: "Read-only SIEM index or export namespace.",
    },
  ],
  "runtime-gateway": [
    {
      name: "stream",
      label: "Event stream",
      placeholder: "runtime-events",
      required: true,
      hint: "Read-only runtime decision log stream.",
    },
  ],
};

export const SYNC_SCHEDULE_FIELD: ConnectorFieldDef = {
  name: "sync_schedule",
  label: "Sync schedule",
  placeholder: "every 15m",
  hint: "Ingest-only cadence: @hourly, @daily, every 15m. Defaults to split ingest/eval when set.",
};

export const EVAL_SCHEDULE_FIELD: ConnectorFieldDef = {
  name: "eval_schedule",
  label: "Eval schedule",
  placeholder: "every 6h",
  hint: "Lake-wide materialize + evaluate cadence (default every 6h when sync is set).",
};

export function schedulerFieldsFor(isRunnable: boolean): ConnectorFieldDef[] {
  return isRunnable ? [SYNC_SCHEDULE_FIELD, EVAL_SCHEDULE_FIELD] : [];
}

export function fallbackCredentialFields(
  credentialType: string,
): ConnectorFieldDef[] {
  if (credentialType.includes("oauth")) {
    const fields: ConnectorFieldDef[] = [
      {
        name: "client_id",
        label: "Client ID",
        placeholder: "client id",
        required: true,
      },
      {
        name: "client_secret_ref",
        label: "Client secret reference",
        placeholder: "TRUSTOPS_CLIENT_SECRET",
        required: true,
      },
    ];
    // Client-credentials grants have no refresh token; must match
    // _missing_required_config in connector_state.py.
    if (!credentialType.includes("client_credentials"))
      fields.push({
        name: "refresh_token_ref",
        label: "Refresh token reference",
        placeholder: "TRUSTOPS_REFRESH_TOKEN",
        required: true,
      });
    return fields;
  }
  if (credentialType.includes("key_pair"))
    return [
      {
        name: "account",
        label: "Account",
        placeholder: "account",
        required: true,
      },
      {
        name: "user",
        label: "User",
        placeholder: "read-only user",
        required: true,
      },
      {
        name: "private_key",
        label: "Private key reference",
        placeholder: "TRUSTOPS_PRIVATE_KEY",
        secret: true,
        required: true,
      },
    ];
  if (credentialType.includes("token"))
    return [
      {
        name: "credential_ref",
        label: "Credential reference",
        placeholder: "TRUSTOPS_API_TOKEN",
        required: true,
        hint: "Environment variable name; raw secrets are not stored in the lake.",
      },
    ];
  if (credentialType.includes("local"))
    return [
      {
        name: "lake_path",
        label: "Lake path",
        placeholder: "/lake/trustops",
        required: true,
      },
    ];
  return [
    {
      name: "api_key",
      label: "API key reference",
      placeholder: "TRUSTOPS_API_KEY",
      required: true,
    },
  ];
}

export function credentialFieldsFor(
  connectorId: string,
  credentialType: string,
): ConnectorFieldDef[] {
  return (
    CONNECTOR_CREDENTIAL_FIELDS[connectorId] ??
    fallbackCredentialFields(credentialType)
  );
}

export function scopeFieldsFor(connectorId: string): ConnectorFieldDef[] {
  return CONNECTOR_SCOPE_FIELDS[connectorId] ?? [];
}
