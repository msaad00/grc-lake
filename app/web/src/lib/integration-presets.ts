export type IntegrationPreset = {
  connectorId: string;
  title: string;
  authLabel: string;
  badges: string[];
  summary: string;
  providerSetup: string;
  trustOpsInput: string;
  advancedTitle: string;
  advancedDetails: string[];
};

const PRESETS: Record<string, IntegrationPreset> = {
  "aws-posture": {
    connectorId: "aws-posture",
    title: "AWS account",
    authLabel: "STS assume-role",
    badges: ["STS", "No long-lived keys"],
    summary:
      "Deploy the customer-owned AWS role, then save the account target. TrustOps verifies STS assume-role after deployment.",
    providerSetup:
      "CloudFormation, Terraform, or StackSets creates a read-only IAM role in the target account.",
    trustOpsInput: "Account ID for the default role, or a full Role ARN.",
    advancedTitle: "Organization rollout",
    advancedDetails: [
      "Use CloudFormation StackSets or Terraform workspaces for many AWS accounts.",
      "Each account sync creates a fresh STS assume-role session with the stored External ID.",
    ],
  },
  "gcp-posture": {
    connectorId: "gcp-posture",
    title: "GCP project",
    authLabel: "Workload identity federation",
    badges: ["Workload identity federation", "No long-lived keys"],
    summary:
      "Apply the read-only Terraform reader identity in your GCP project, then enter the project ID to stage the connector.",
    providerSetup:
      "Terraform grants Cloud Asset and IAM read permissions to the TrustOps workload identity.",
    trustOpsInput: "Project ID for the target project.",
    advancedTitle: "Folder or organization rollout",
    advancedDetails: [
      "Apply the same reader module across projects from Terraform or your platform workspace.",
      "TrustOps probes the configured project before sync lands IAM and asset posture evidence.",
    ],
  },
  "azure-posture": {
    connectorId: "azure-posture",
    title: "Azure subscription",
    authLabel: "Reader role",
    badges: ["Reader role", "No long-lived keys"],
    summary:
      "Grant Reader to the TrustOps Entra app or workload identity, then confirm the subscription. Scheduled sync uses fresh Azure tokens; no passwords are stored.",
    providerSetup:
      "Azure Cloud Shell grants Reader at subscription or management-group scope.",
    trustOpsInput:
      "Subscription ID printed by setup or returned after admin consent.",
    advancedTitle: "Management-group rollout",
    advancedDetails: [
      "Use management-group scope when the same TrustOps identity should read many subscriptions.",
      "No Azure password or client secret is stored in TrustOps.",
    ],
  },
  "intune-devices": {
    connectorId: "intune-devices",
    title: "Intune devices",
    authLabel: "Graph read-only permission",
    badges: ["DeviceManagementManagedDevices.Read.All", "No long-lived keys"],
    summary:
      "Grant the TrustOps Entra app or managed identity the Graph application permission DeviceManagementManagedDevices.Read.All, then confirm the tenant. Sync reads encryption, compliance, and jailbreak state only.",
    providerSetup:
      "An Entra admin grants admin consent for DeviceManagementManagedDevices.Read.All on the TrustOps app registration.",
    trustOpsInput: "Microsoft Entra tenant ID.",
    advancedTitle: "What is collected",
    advancedDetails: [
      "Device ID and name, user principal name, OS and version, ownership, encryption, compliance, and jailbreak state.",
      "Hardware identifiers (IMEI, serial, MAC), phone numbers, and admin notes are never requested.",
    ],
  },
  "bamboohr-personnel": {
    connectorId: "bamboohr-personnel",
    title: "BambooHR employees",
    authLabel: "Dedicated read-only user",
    badges: ["Minimal HR fields", "Secret reference only"],
    summary:
      "Create a BambooHR user whose access level can view only employment fields, store its API key as a secret, then enter the company domain. Sync reads status, hire and termination dates, department, and manager.",
    providerSetup:
      "A BambooHR admin creates a dedicated user with a custom access level limited to the employment fields, then generates its API key.",
    trustOpsInput: "Company domain and the API key secret reference.",
    advancedTitle: "What is collected",
    advancedDetails: [
      "Employee ID and number, work email, employment status, hire and termination dates, department, and manager ID.",
      "Names, dates of birth, government IDs, compensation, addresses, and personal contact details are never requested.",
    ],
  },
  "rippling-personnel": {
    connectorId: "rippling-personnel",
    title: "Rippling workers",
    authLabel: "workers.read token",
    badges: ["workers.read only", "Secret reference only"],
    summary:
      "Create a Rippling API token limited to the workers.read scope and store it as a secret. Sync keeps worker status, start and end dates, department, and manager; every other field is discarded before anything is stored.",
    providerSetup:
      "A Rippling admin creates an API token with only the workers.read scope.",
    trustOpsInput: "The API token secret reference.",
    advancedTitle: "What is collected",
    advancedDetails: [
      "Worker ID and number, work email, status, start and end dates, department ID, and manager ID.",
      "Date of birth, gender, compensation, personal email, and all other worker fields are never stored.",
    ],
  },
  "workday-personnel": {
    connectorId: "workday-personnel",
    title: "Workday employment report",
    authLabel: "Integration system user",
    badges: ["RaaS report", "Secret reference only"],
    summary:
      "Build a Workday custom report with the TrustOps column contract, share it with a read-only integration system user, and enter its JSON URL. Only the contract columns are stored.",
    providerSetup:
      "A Workday admin creates the custom report, enables it as a web service, and grants the integration system user view access.",
    trustOpsInput:
      "Report JSON URL, integration system user, and its password secret reference.",
    advancedTitle: "Report column contract",
    advancedDetails: [
      "Employee_ID, Work_Email, Worker_Status, Hire_Date, Termination_Date, Department, Manager_ID.",
      "Any other report column is ignored and never stored.",
    ],
  },
  "jamf-devices": {
    connectorId: "jamf-devices",
    title: "Jamf Pro devices",
    authLabel: "API client (read-only role)",
    badges: ["Read Computers", "Read Mobile Devices", "Secret reference only"],
    summary:
      "Create a Jamf Pro API role with only Read Computers and Read Mobile Devices, assign it to an API client, store the client secret, then enter the Jamf Pro URL and client ID. Sync reads encryption, OS version, passcode, firewall, and check-in state.",
    providerSetup:
      "A Jamf Pro admin creates the API role and API client under Settings > System > API roles and clients, enables the client, and generates its secret.",
    trustOpsInput:
      "Jamf Pro URL, API client ID, and the client secret reference.",
    advancedTitle: "What is collected",
    advancedDetails: [
      "Device ID and name, platform, OS version, FileVault or data-protection state, firewall, passcode compliance, managed and check-in state, and the assigned user's email.",
      "IP addresses, serial numbers, usernames, real names, phone numbers, recovery keys, and locations are dropped before anything is stored.",
    ],
  },
  "crowdstrike-falcon": {
    connectorId: "crowdstrike-falcon",
    title: "CrowdStrike Falcon",
    authLabel: "API client (read scopes)",
    badges: ["Hosts: Read", "Prevention policies: Read", "Alerts: Read"],
    summary:
      "Create a Falcon API client with the Hosts, Prevention policies, and Alerts read scopes, store its secret, then enter the cloud and client ID. Sync reads sensor coverage, prevention policy status, and unresolved alert counts.",
    providerSetup:
      "A Falcon administrator creates an API client with only the three read scopes.",
    trustOpsInput:
      "Falcon cloud, API client ID, and the client secret reference.",
    advancedTitle: "What is collected",
    advancedDetails: [
      "Host ID and name, platform, OS and sensor version, last seen, reduced functionality mode, and prevention policy; unresolved alert counts by severity for the last 30 days.",
      "MAC and IP addresses, serial numbers, user names, and alert details beyond status and severity are never stored.",
    ],
  },
  "kubernetes-cluster": {
    connectorId: "kubernetes-cluster",
    title: "Kubernetes cluster",
    authLabel: "Read-only ClusterRole",
    badges: ["get/list only", "No Secret access"],
    summary:
      "Bind a dedicated service account to a get/list-only ClusterRole, then name the cluster. Sync reads RBAC bindings, pod security settings, network policies, image sources, and API server audit flags where visible.",
    providerSetup:
      "A cluster admin applies the trustops-config-reader ClusterRole and binding (docs/CONNECTORS.md), then issues a kubeconfig for that identity or runs TrustOps in-cluster.",
    trustOpsInput:
      "Cluster name, optional kubeconfig context and path reference, optional allowed registries.",
    advancedTitle: "What is collected",
    advancedDetails: [
      "Binding subjects, workload security settings, image references, names of Secret-backed env vars, NetworkPolicy counts, and audit flag presence.",
      "Secrets, env values, container arguments, labels, and annotations are never read or stored.",
    ],
  },
  "knowbe4-training": {
    connectorId: "knowbe4-training",
    title: "KnowBe4 training",
    authLabel: "Reporting API key",
    badges: ["Read-only reporting", "Secret reference only"],
    summary:
      "Generate a Reporting API key in the KnowBe4 console, store it as a secret, then pick the account region. Sync reads training enrollment status and phishing test results.",
    providerSetup:
      "A KnowBe4 admin generates a Reporting API key. It requires a Platinum, Diamond, SAT Foundation, or SAT Advanced subscription.",
    trustOpsInput: "Region and the API key secret reference.",
    advancedTitle: "What is collected",
    advancedDetails: [
      "User ID, email, employee number, enrollment status counts, last completion date, and phish-prone percentage.",
      "Names, phone numbers, locations, manager details, and custom fields are never stored.",
    ],
  },
  "databricks-evidence-lake": {
    connectorId: "databricks-evidence-lake",
    title: "Databricks evidence lake",
    authLabel: "Service principal (OAuth M2M)",
    badges: ["Unity Catalog SELECT only", "Short-lived tokens"],
    summary:
      "Run the Unity Catalog bootstrap to create the four TrustOps evidence views, grant a service principal CAN USE on one SQL warehouse and SELECT on the views, then enter the workspace, warehouse, and schema.",
    providerSetup:
      "deploy/databricks/bootstrap_poc.sql creates the views over system.access.audit and the read grants; a workspace admin grants CAN USE on the SQL warehouse.",
    trustOpsInput:
      "Workspace host, SQL warehouse ID, catalog, schema, and the service principal's application ID and secret reference.",
    advancedTitle: "How reads work",
    advancedDetails: [
      "Reads use the SQL Statement Execution API; no driver or SDK is installed.",
      "OAuth tokens last one hour and are minted per sync; nothing is written to the workspace.",
    ],
  },
  "bigquery-evidence-lake": {
    connectorId: "bigquery-evidence-lake",
    title: "BigQuery evidence lake (preview)",
    authLabel: "Workload identity / ADC",
    badges: ["Read-only queries", "Bytes-billed cap"],
    summary:
      "Read security tables you already keep in BigQuery. Grant the runtime identity BigQuery Job User on the query project and Data Viewer on the dataset, then supply a mapping through the API or CLI.",
    providerSetup:
      "Attach a service account (or workload identity) with roles/bigquery.jobUser on the query project and roles/bigquery.dataViewer on the source dataset.",
    trustOpsInput:
      "Query project ID, optional default dataset and location, and a mapping (a preset such as ocsf/api_activity or your own spec).",
    advancedTitle: "How reads work",
    advancedDetails: [
      "Each mapping runs one parameterized SELECT; values are bound as query parameters.",
      "Every query sets maximum_bytes_billed, so an oversized scan fails instead of running.",
    ],
  },
  "iceberg-parquet-lake": {
    connectorId: "iceberg-parquet-lake",
    title: "Iceberg / Parquet lake (preview)",
    authLabel: "Read-only IAM role or catalog token",
    badges: ["Read-only scans", "OCSF presets"],
    summary:
      "Point TrustOps at the Iceberg tables or Parquet data you already run. For Amazon Security Lake, choose Glue and the region; the OCSF presets map CloudTrail and Security Hub tables to evidence.",
    providerSetup:
      "Grant a read-only role glue:GetDatabase and glue:GetTable on the lake database plus s3:GetObject and s3:ListBucket on the data prefix, or issue a short-lived REST catalog token.",
    trustOpsInput:
      "Source type, region or catalog URI, optional role ARN, and, for sources other than Security Lake, a mapping supplied through the API or CLI.",
    advancedTitle: "How reads work",
    advancedDetails: [
      "Filters and the watermark are pushed into Iceberg or Parquet scans; nothing is written to the lake.",
      "The first sync reads a recent window; later syncs continue from the watermark with a lookback for late data.",
    ],
  },
  "snowflake-evidence-lake": {
    connectorId: "snowflake-evidence-lake",
    title: "Snowflake evidence lake",
    authLabel: "Key-pair or OAuth reference",
    badges: ["Key-pair or OAuth reference", "Secret reference only"],
    summary:
      "Connect a read-only Snowflake service identity, discover visible objects, then select the evidence views.",
    providerSetup:
      "Create a service user and role with USAGE plus SELECT on the evidence database, schema, and views.",
    trustOpsInput:
      "Account, service user, and secret reference for a mounted key-pair or OAuth token.",
    advancedTitle: "Evidence view mapping",
    advancedDetails: [
      "Discovery shows only objects visible to the read-only role.",
      "Advanced view names stay collapsed unless the warehouse schema is custom.",
    ],
  },
  "okta-identity": {
    connectorId: "okta-identity",
    title: "Okta identity",
    authLabel: "Okta API token reference",
    badges: ["Okta API token reference", "Read-only scopes"],
    summary:
      "Use a scoped Okta token reference to read users, factors, and MFA policy evidence.",
    providerSetup:
      "Create a read-only Okta API token with users, factors, and policy read scopes.",
    trustOpsInput: "Okta org URL and the runtime secret reference name.",
    advancedTitle: "System Log option",
    advancedDetails: [
      "Use Okta System Log as a separate event-stream connector when login events are needed.",
      "TrustOps stores the reference name, not the token value.",
    ],
  },
  "okta-system-log": {
    connectorId: "okta-system-log",
    title: "Okta System Log",
    authLabel: "Okta API token reference",
    badges: ["Okta API token reference", "Event stream"],
    summary:
      "Use a scoped Okta token reference to read authentication and session events.",
    providerSetup: "Grant okta.logs.read to a service token in Okta.",
    trustOpsInput: "Okta org URL and the runtime secret reference name.",
    advancedTitle: "Event freshness",
    advancedDetails: [
      "System Log has a shorter freshness SLO than identity posture.",
      "Keep the token read-only and rotate it in your secret manager.",
    ],
  },
  "identity-provider": {
    connectorId: "identity-provider",
    title: "Entra identity",
    authLabel: "Entra app or workload identity",
    badges: ["Entra app or workload identity", "Read-only directory"],
    summary:
      "Use provider-native OAuth client credentials or workload identity to read users, groups, assignments, and access reviews.",
    providerSetup:
      "Register an Entra application or managed identity with read-only Graph permissions.",
    trustOpsInput:
      "Tenant, client identity, and secret or federated credential reference.",
    advancedTitle: "SSO provider preset",
    advancedDetails: [
      "Use the same preset pattern for Okta, Entra, and Google Workspace identity sources.",
      "Human console SSO is separate from read-only evidence collection.",
    ],
  },
  "google-workspace-identity": {
    connectorId: "google-workspace-identity",
    title: "Google Workspace identity",
    authLabel: "Google Workspace OAuth reference",
    badges: ["Google Workspace OAuth reference", "Read-only directory"],
    summary:
      "Use a mounted OAuth token reference to read Workspace users, groups, and MFA posture.",
    providerSetup:
      "Authorize read-only Admin SDK Directory scopes for a service identity.",
    trustOpsInput:
      "Workspace customer ID, plus either a runtime OAuth token reference or the refresh token, client ID, and client secret for unattended sync.",
    advancedTitle: "Directory scopes",
    advancedDetails: [
      "Use directory.users.readonly, directory.groups.readonly, and directory.user.security.readonly.",
      "TrustOps stores the reference name, not the token value.",
      "Unattended sync needs all three refresh fields; TrustOps mints access tokens on demand and never persists them.",
    ],
  },
};

export function getIntegrationPreset(
  connectorId: string,
): IntegrationPreset | null {
  return PRESETS[connectorId] ?? null;
}
