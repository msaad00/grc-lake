"""Regression contract for clear cloud-account linking in the console."""

from pathlib import Path

ROOT = Path(__file__).parents[1]
PANEL = ROOT / "app/web/src/components/connectors/CloudLinkPanel.tsx"
DRAWER = ROOT / "app/web/src/components/drawers/ConnectorDrawer.tsx"
VALIDATION = ROOT / "app/web/src/lib/cloud-link-validation.ts"
DRAWER_SHELL = ROOT / "app/web/src/components/ui/drawer.tsx"


def test_connected_cloud_drawer_stays_compact_at_narrow_widths() -> None:
    drawer = DRAWER.read_text(encoding="utf-8")
    shell = DRAWER_SHELL.read_text(encoding="utf-8")

    assert '"w-[min(560px,calc(100vw-16px))]"' in shell
    assert '"flex-1 overflow-auto px-4 py-5 sm:px-5"' in shell
    # With a sticky footer the scroll area pads its end so the last field clears it.
    assert 'footer && "scroll-pb-24 pb-10"' in shell
    assert 'className="border-t border-line px-4 py-3 sm:px-5"' in shell
    assert 'size="sm"' in drawer
    assert 'aria-label="Connected connector view"' in drawer


def test_aws_linking_explains_authorization_and_role_boundary() -> None:
    panel = PANEL.read_text(encoding="utf-8")

    assert "GRC Lake verifies STS assume-role after deployment." in panel
    assert "Deploy the customer-owned AWS role, then save the account target." in panel
    assert "Open AWS guided deploy" in panel
    assert "AWS Console" in panel
    assert "CloudFormation CLI" in panel
    assert "Terraform CLI" in panel
    assert "Deployment method" in panel
    assert "Deploy role" not in panel
    assert "Copy script" in panel
    assert "View script" in panel
    assert "Run in the target AWS account; the final line prints" not in panel
    assert "AWS account" in panel
    assert "Read-only AWS role" not in panel
    assert 'useState<AwsDeployMode>("cloudformation")' in panel
    assert 'setAwsDeployMode("cloudformation")' in panel
    assert "AWS CLI deploy command" not in panel
    assert "Copy Terraform command" in panel
    assert "sanitizeAwsRoleName" in panel
    assert "awsQuickCreateUrl" in panel
    assert "awsTerraformCommand" in panel
    assert "Advanced options" not in panel
    assert "Advanced role settings" not in panel
    assert "Read-only IAM posture" in panel
    assert "IAM posture read-only" in panel
    assert "session.cloudshell_command" in panel
    assert "YOUR_GRC_LAKE_PRINCIPAL_ARN" not in panel
    assert "TemplateURL" not in panel
    assert "Next: verify access" in panel
    assert "Save AWS account" not in panel
    assert "Back" in panel
    assert "resetSetup" in panel
    assert "Stage credentials" not in panel
    assert "Account ID or Role ARN" in panel
    assert "Confirm account ID" not in panel
    assert "Scale or custom role" not in panel
    assert "One AWS account" in panel
    assert "Many accounts: deploy" not in panel
    assert "CloudFormation StackSets or" in panel
    assert "Use the account ID when the script keeps the default role name." not in panel
    assert "Default role: account ID. Custom role: full ARN." not in panel
    assert "Use a custom Role ARN" not in panel
    assert "3. Add account targets" in panel
    assert "View permissions" in panel
    assert "Organization rollout" not in panel
    assert "Scale with StackSets or Terraform" not in panel
    assert "CloudFormation StackSets" in panel
    assert "Terraform workspaces" in panel
    assert "Bulk account import" not in panel
    assert "Selected accounts" in panel
    assert "Add another account" in panel
    assert "View trust details" not in panel
    assert "AWS role ARN" not in panel
    assert "Deploy links unavailable" not in panel
    assert "GRC_LAKE_AWS_TEMPLATE_URL" not in panel
    assert 'aria-label="AWS deployment method"' not in panel


def test_aws_onboarding_is_a_guided_multi_account_wizard() -> None:
    panel = PANEL.read_text(encoding="utf-8")
    drawer = DRAWER.read_text(encoding="utf-8")

    assert 'type AwsAccountScope = "single" | "organization" | "selected"' in panel
    assert "Choose what you want to connect" not in panel
    assert "One AWS account" in panel
    assert "AWS Organization" in panel
    assert "Selected accounts" in panel
    assert "Best for getting started" in panel
    assert "CloudFormation StackSets" in panel
    assert "Add another account" in panel
    assert "3. Add account targets" in panel
    assert "Copy script" in panel
    assert "Customize role" in panel
    assert "1. Choose scope" in panel
    assert "2. Deploy read-only access" in panel
    assert "3. Add account targets" in panel
    assert "4. Verify and finish" in panel
    assert "Snowflake runs a live probe" not in drawer
    assert "GRC Lake will call AWS STS AssumeRole" in drawer


def test_aws_linking_accepts_account_id_or_role_arn() -> None:
    validation = VALIDATION.read_text(encoding="utf-8")
    panel = PANEL.read_text(encoding="utf-8")

    assert "awsRoleIdentifierError" in validation
    assert "awsRoleArnFromIdentifier" in validation
    assert 'trimmed.startsWith("arn:")' in validation
    assert "/^[0-9\\s-]+$/" in validation
    assert "AWS account ID must be exactly 12 digits." in validation
    assert "return `arn:aws:iam::${accountId}:role/${roleName}`;" in validation
    assert "awsRoleArnFromIdentifier(awsRoleIdentifier, awsRoleName)" in panel
    assert "awsRoleIdentifierError(awsRoleIdentifier)" in panel
    assert 'placeholder="AWS account ID or role ARN"' in panel
    assert 'placeholder="030225640638"' not in panel
    assert 'placeholder="arn:aws:iam::123456789012:role/CustomGrcLakeRole"' not in panel


def test_azure_linking_is_provider_identity_first() -> None:
    panel = PANEL.read_text(encoding="utf-8")
    forms = (ROOT / "app/web/src/lib/connector-forms.ts").read_text(encoding="utf-8")
    readme = (ROOT / "docs/CONNECTOR_CREDENTIALS.md").read_text(encoding="utf-8")
    live_poc = (ROOT / "docs/LIVE_CLOUD_POC.md").read_text(encoding="utf-8")

    assert "Read-only Azure identity" in panel
    assert "Deploy Azure access" in panel
    assert "Copy Cloud Shell setup" in panel
    assert "View command" in panel
    assert "GRC_LAKE_AZURE_APP_ID" in panel
    assert "session.azure_app_id" in panel
    assert "GRC_LAKE_AZURE_PRINCIPAL_OBJECT_ID" in panel
    assert "Set GRC_LAKE_AZURE_APP_ID or GRC_LAKE_AZURE_PRINCIPAL_OBJECT_ID" in panel
    assert "--role Reader" in panel
    assert "management-group" in panel
    assert "No Azure password or" in panel
    assert "client secret is stored" in panel
    assert "Next: verify access" in panel
    assert "Save cloud connection" not in panel
    assert "Azure Cloud Shell setup" not in panel
    assert "Grants Reader to the GRC Lake app or managed identity." not in panel
    assert "The final line prints the IDs to confirm below." not in panel
    assert "local az login" not in panel
    assert "Use my laptop login" not in panel

    assert "Confirm the subscription after granting Reader" in forms
    assert "Customer-owned Entra application" not in forms
    assert "**Azure**" in readme
    assert "managed identity, or federated workload identity" in readme
    assert "No connector requires pasted long-lived cloud keys." not in readme
    assert "Cloud connectors use short-lived or workload identity credentials" in readme
    assert "a service-account key file also works" in readme
    assert "use scoped API tokens or an integration-user login" in readme
    assert "not the secret itself" in readme
    assert "Local `az login` is acceptable for developer proof only." in live_poc
    assert "Do not present it as" in live_poc


def test_snowflake_linking_uses_secret_references_not_passwords() -> None:
    drawer = DRAWER.read_text(encoding="utf-8")
    forms = (ROOT / "app/web/src/lib/connector-forms.ts").read_text(encoding="utf-8")
    readme = (ROOT / "docs/CONNECTOR_CREDENTIALS.md").read_text(encoding="utf-8")

    assert "Read-only Snowflake role" in drawer
    assert "Secret reference only" in drawer
    assert "identity ready" in drawer
    assert "scope discovered" in drawer
    assert "Key-pair or OAuth reference; no pasted private key." in drawer
    assert "Use SSO for a human proof or a service user with key-pair/OAuth" not in drawer
    assert "Connect with a read-only Snowflake service identity." not in drawer
    assert "do not paste a key or password" in forms
    assert "Snowflake is one of the existing-lake readers." in readme
    assert "the existing security-data-lake path" not in readme
    assert "key-pair or OAuth token reference" in readme
    assert "not passwords or private-key contents" in readme


def test_enabled_cloud_connector_hides_onboarding_and_duplicate_credentials() -> None:
    drawer = DRAWER.read_text(encoding="utf-8")

    assert "const usesManagedCloudLink = supportsCloudLink(connector.connector_id);" in drawer
    assert "const showCloudLinkPanel =" in drawer
    assert "!isEnabled || (isEnabled && editCloudSetup)" in drawer
    assert "(isEnabled && editCloudSetup)" in drawer
    assert "<CloudLinkPanel" in drawer
    assert "!usesManagedCloudLink && (" in drawer
    assert "Edit setup" in drawer
    assert "Hide setup" in drawer


def test_enabled_cloud_connector_can_edit_and_reverify_setup() -> None:
    drawer = DRAWER.read_text(encoding="utf-8")

    assert "const hasPendingConfigChanges =" in drawer
    assert "isEnabled && !hasPendingConfigChanges" in drawer
    assert "? latestProbeOk" in drawer
    assert "hasPendingConfigChanges" in drawer
    assert ": probeGateSatisfied" in drawer
    assert "payload.credentials = stagedCredentials;" in drawer
    assert "hasPendingConfigChanges && !probeGateSatisfied" in drawer
    assert "Test connection before saving these changes." in drawer
    assert "setCreds({});" in drawer
    assert "setSavedOptionsBaseline(stagedOptions);" in drawer
    assert "Save changes" in drawer
    assert "New setup staged" in drawer
    assert "Test connection, then save changes." in drawer
    assert "Edit setup" in drawer
    assert "Add another account" not in drawer


def test_cloud_link_setup_uses_one_compact_step_pattern() -> None:
    panel = PANEL.read_text(encoding="utf-8")

    assert "Deploy role" not in panel
    assert "Deploy Azure access" in panel
    assert "Deploy GCP access" in panel
    assert panel.count("View command") >= 2
    assert "Terraform deploy command" not in panel
    assert "Download Terraform template" not in panel
    assert "Copy Terraform command" in panel
    assert "Save cloud connection" not in panel
    assert "Next: verify access" in panel


def test_integration_wizard_has_provider_presets_for_cloud_data_and_sso() -> None:
    presets = (ROOT / "app/web/src/lib/integration-presets.ts").read_text(encoding="utf-8")
    panel = (ROOT / "app/web/src/components/connectors/IntegrationPresetPanel.tsx").read_text(encoding="utf-8")
    drawer = DRAWER.read_text(encoding="utf-8")
    cloud = PANEL.read_text(encoding="utf-8")

    for connector_id in (
        "aws-posture",
        "gcp-posture",
        "azure-posture",
        "snowflake-evidence-lake",
        "okta-identity",
        "identity-provider",
        "google-workspace-identity",
    ):
        assert connector_id in presets

    assert "Integration wizard" in panel
    assert "Provider setup" in panel
    assert "GRC Lake needs" in panel
    assert "Advanced provider details" in panel
    assert "No long-lived keys" in presets
    assert "STS assume-role" in presets
    assert "Workload identity federation" in presets
    assert "Reader role" in presets
    assert "Key-pair or OAuth reference" in presets
    assert "Okta API token reference" in presets
    assert "Entra app or workload identity" in presets
    assert "Google Workspace OAuth reference" in presets
    assert "getIntegrationPreset" in cloud
    assert "getIntegrationPreset" in drawer
    assert "<IntegrationPresetPanel" in drawer
    assert "showIntegrationPreset" in drawer


def test_onboarding_cloud_connector_reopens_setup_even_with_staged_target() -> None:
    drawer = DRAWER.read_text(encoding="utf-8")

    assert "const showingFirstTimeCloudSetup =" in drawer
    assert "usesManagedCloudLink && onboarding && !isEnabled" in drawer
    assert "!isEnabled || (isEnabled && editCloudSetup)" in drawer
    assert "!showingFirstTimeCloudSetup" in drawer
    assert 'setupTab === "Runs"' in drawer
    assert "const showSetupProgressCard =" in drawer
    assert "const showSetupProgressCard = !showCloudLinkPanel;" in drawer
    assert "showSetupProgressCard && (" in drawer
    assert "onboarding && !showingFirstTimeCloudSetup" in drawer


def test_aws_drawer_has_one_linear_setup_flow_and_no_duplicate_sync_action() -> None:
    drawer = DRAWER.read_text(encoding="utf-8")

    labels = [drawer.index(f'label: "{label}"') for label in ("Authorize", "Verify", "Scope", "Sync")]
    assert labels == sorted(labels)
    assert 'label: "Access"' not in drawer
    assert 'label: "Validate"' not in drawer
    assert drawer.count("Sync evidence") == 1
    assert "const showDiscoveryAction = !usesManagedCloudLink && needsDiscovery;" in drawer
    assert "{showDiscoveryAction ? (" in drawer


def test_disabled_cloud_drawer_separates_setup_runs_and_events() -> None:
    drawer = DRAWER.read_text(encoding="utf-8")

    assert 'const SETUP_TABS = ["Setup", "Runs", "Events"] as const;' in drawer
    assert 'useState<SetupTab>("Setup")' in drawer
    assert 'aria-label="Connector setup view"' in drawer
    assert 'setupTab === "Setup"' in drawer
    assert 'setupTab === "Runs"' in drawer
    assert 'setupTab === "Events"' in drawer
    assert "Run history" in drawer
    assert "Configuration events" in drawer
    assert "LatestSyncProof" in drawer
    assert "Run log ·" not in drawer


def test_managed_cloud_drawer_uses_progressive_disclosure() -> None:
    drawer = DRAWER.read_text(encoding="utf-8")

    assert "const showManagedCloudConfiguration =" in drawer
    assert "showCloudLinkPanel &&" in drawer
    assert "!showInlineCloudSetup && (" in drawer
    assert "<CloudLinkPanel" in drawer
    assert "(!usesManagedCloudLink || showManagedCloudConfiguration)" in drawer
    assert '<summary className="ui-label cursor-pointer list-none">' in drawer
    assert "Scope & automation" in drawer
    assert 'className="mt-3 grid items-start gap-2 2xl:grid-cols-[minmax(0,1fr)_minmax(18rem,0.72fr)]"' in drawer
    assert 'setupTab === "Events"' in drawer
    assert 'setupTab === "Setup"' in drawer


def test_aws_probe_errors_are_actionable_in_drawer() -> None:
    drawer = DRAWER.read_text(encoding="utf-8")

    assert "function runErrorDetail" in drawer
    assert "AWS STS probe failed." in drawer
    assert "role trust policy" in drawer
    assert "network access to AWS STS" in drawer
    assert "Configure AWS credentials for the GRC Lake runtime" in drawer
    assert "Probe error: ${runErrorDetail(run)}" in drawer


def test_connected_cloud_drawer_is_compact_and_non_redundant() -> None:
    drawer = DRAWER.read_text(encoding="utf-8")

    assert "const showConnectedCloudSummary =" in drawer
    assert "usesManagedCloudLink && isEnabled;" in drawer
    assert 'aria-label="Connected connector view"' in drawer
    assert '"Overview", "Config", "Runs"' in drawer
    assert '"Overview", "Details", "History"' not in drawer
    assert "connectedTab ===" in drawer
    assert "compact?: boolean" in drawer
    assert "<LatestSyncProof" in drawer
    assert "runnable={isRunnable}" in drawer
    assert "compact\n                />" in drawer
    assert "rounded-full border border-line bg-panel px-2.5 py-1" in drawer
    assert "Connection details" in drawer
    assert "Schedule and scope" in drawer
    assert "Authorization" in drawer
    assert "Read-only role" in drawer
    assert "STS per run" in drawer
    assert "Organization rollout" in drawer
    assert "Every probe, sync, and scheduled run creates a fresh AWS" in drawer
    assert "Connector run log" in drawer
    assert "Sync lands raw connector evidence." in drawer
    assert "Eval produces gold" in drawer
    assert "controls, pass/fail metrics, and proof exports." in drawer
    assert "showConnectedCloudSummary ? (" in drawer
    assert "max-h-80 overflow-auto" in drawer
    assert "open={!usesManagedCloudLink && !showConnectedCloudSummary}" in drawer
    assert "Run history" in drawer
    assert "see history" not in drawer


def _ts_string_array(source: str, name: str) -> list[str]:
    import re

    match = re.search(rf"export const {name} = \[(.*?)\] as const;", source, re.S)
    assert match, name
    return re.findall(r'"([^"]*)"', match.group(1))


def _ts_regex(source: str, name: str) -> str:
    import re

    match = re.search(rf"const {name} =\s*/(.*?)/;", source, re.S)
    assert match, name
    return match.group(1)


def test_console_hosted_validation_mirrors_the_server_rules() -> None:
    from security_lakehouse import delegation, secret_refs

    validation = VALIDATION.read_text(encoding="utf-8")
    assert _ts_string_array(validation, "SERVER_SECRET_PREFIXES") == list(secret_refs.DENIED_PREFIXES)
    assert set(_ts_string_array(validation, "SERVER_SECRET_NAMES")) == set(secret_refs.DENIED_NAMES)
    assert _ts_regex(validation, "ENV_NAME_RE") == f"^{secret_refs.ENV_NAME_RE.pattern}$"
    assert _ts_regex(validation, "AZURE_TENANT_RE") == delegation._AZURE_TENANT_ID.pattern  # noqa: SLF001
    assert _ts_regex(validation, "AZURE_CLIENT_RE") == delegation._AZURE_CLIENT_ID.pattern  # noqa: SLF001
    assert (
        _ts_regex(validation, "GCP_SERVICE_ACCOUNT_RE").replace("\\.", ".")
        == delegation._SERVICE_ACCOUNT_EMAIL.pattern.replace("\\.", ".")  # noqa: SLF001
    )
    assert secret_refs.TENANT_PREFIX_ROOT + "<ID>__" in validation


def test_hosted_cloud_link_panel_collects_delegation_and_never_trusts_the_callback() -> None:
    panel = PANEL.read_text(encoding="utf-8")

    assert "useCredentialPolicy" in panel
    assert "session?.delegation" in panel
    assert "delegation: delegationPayload()" in panel
    assert "impersonate_service_account:" in panel
    assert "tenant_id: azureTenantId.trim()" in panel
    assert "client_id: azureClientId.trim()" in panel
    assert "[azureSecretKind]: azureSecretRef.trim()" in panel
    # The consent callback's tenant is unauthenticated input; never pre-fill it.
    assert "azure_tenant_id" not in panel
    assert "Environment variable name" in panel
    assert 'type="password"' not in panel
