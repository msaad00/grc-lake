"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  AlertCircle,
  CheckCircle2,
  KeyRound,
  ListChecks,
  Loader2,
  PauseCircle,
  PlayCircle,
  RefreshCw,
  Search,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { BRAND } from "@/lib/brand";
import { Button } from "@/components/ui/button";
import { Drawer } from "@/components/ui/drawer";
import {
  useConfigureMutation,
  useConnectorRuns,
  useDiscoverMutation,
  useProbeMutation,
  useSyncMutation,
} from "@/lib/api/hooks";
import { useAuditorMode } from "@/lib/state/auditor";
import type {
  ConfigurePayload,
  ConnectorRun,
  ConnectorView,
  ProbePayload,
} from "@/lib/api/types";
import { ConnectorMark } from "@/components/connectors/ConnectorMark";
import { OnboardingGuideBanner } from "@/components/onboarding/OnboardingGuideBanner";
import {
  CloudLinkPanel,
  supportsCloudLink,
} from "@/components/connectors/CloudLinkPanel";
import { IntegrationPresetPanel } from "@/components/connectors/IntegrationPresetPanel";
import {
  credentialFieldsFor,
  schedulerFieldsFor,
  scopeFieldsFor,
  type ConnectorFieldDef,
} from "@/lib/connector-forms";
import { getIntegrationPreset } from "@/lib/integration-presets";

interface Props {
  connector: ConnectorView | null;
  linkSessionId?: string | null;
  onboarding?: boolean;
  onClose: () => void;
  onToast: (msg: string) => void;
}

type FieldDef = ConnectorFieldDef;

interface SetupStep {
  label: string;
  detail: string;
  tone: "ready" | "attention" | "default";
}

const CONNECTED_TABS = ["Overview", "Config", "Runs"] as const;
type ConnectedTab = (typeof CONNECTED_TABS)[number];
const SETUP_TABS = ["Setup", "Runs", "Events"] as const;
type SetupTab = (typeof SETUP_TABS)[number];

const isRunnableConnector = (connector: ConnectorView) =>
  Boolean(connector.is_implemented);

function probeToastMessage(run: ConnectorRun, isEnabled: boolean): string {
  if (run.result === "ok") {
    const mode = run.metadata?.probe_mode;
    if (mode === "live") {
      return isEnabled
        ? "Live connection verified."
        : "Live connection verified. You can enable this connector.";
    }
    if (mode === "config_only") {
      return isEnabled
        ? "Configuration validated (no live vendor call)."
        : "Configuration shape validated — run a live probe after enabling credentials.";
    }
    return isEnabled
      ? "Probe ok."
      : "Access test passed. You can enable this connector.";
  }
  if (run.result === "skipped") {
    return `Contract validated: ${run.error ?? "probe skipped"}`;
  }
  return `Probe error: ${runErrorDetail(run)}`;
}

function runCoverageGapMessages(run: ConnectorRun): string[] {
  const gaps = run.metadata?.coverage_gaps;
  if (!Array.isArray(gaps)) return [];
  return gaps
    .map((gap) =>
      gap && typeof gap === "object" && "message" in gap
        ? String((gap as { message?: unknown }).message ?? "")
        : "",
    )
    .filter(Boolean);
}

function RunCoverageGaps({ run }: { run: ConnectorRun }) {
  const messages = runCoverageGapMessages(run);
  if (messages.length === 0) return null;
  return (
    <div className="mt-1 text-warning-fg">
      <div className="font-medium">
        Partial collection · {messages.length} coverage gap
        {messages.length === 1 ? "" : "s"}
      </div>
      <ul className="mt-0.5 list-disc pl-4">
        {messages.map((message) => (
          <li key={message}>{message}</li>
        ))}
      </ul>
    </div>
  );
}

function runErrorDetail(run: ConnectorRun, connector?: ConnectorView): string {
  const error = run.error?.trim();
  if (!error) return "see connector runs";
  const isAws =
    connector?.connector_id === "aws-posture" || error.includes("AssumeRole");
  if (!isAws) return error;
  if (error === "ClientError") {
    return "AWS STS probe failed. Check that the TrustOps runtime can reach AWS, has AWS credentials, and the deployed role trusts this runtime principal with the current External ID.";
  }
  if (error.includes("AccessDenied") || error.includes("not authorized")) {
    return `${error} Check the role trust policy, TrustedPrincipalArn, External ID, and role ARN/account ID.`;
  }
  if (
    error.includes("EndpointConnectionError") ||
    error.includes("Could not connect")
  ) {
    return `${error} Check that the TrustOps runtime has network access to AWS STS.`;
  }
  if (
    error.includes("NoCredentialsError") ||
    error.includes("PartialCredentialsError")
  ) {
    return `${error} Configure AWS credentials for the TrustOps runtime principal before probing.`;
  }
  return error;
}

function validateStepDetail(
  connector: ConnectorView,
  latestProbeOk: boolean,
): string {
  if (!latestProbeOk) return "Run test";
  const mode = connector.last_probe?.metadata?.probe_mode;
  if (mode === "live") return "Live connection verified";
  if (mode === "config_only") return "Configuration validated";
  if (mode === "contract_only") return "Contract validated";
  return "Connection checked";
}

const toneForResult = (r: string | undefined) =>
  r === "ok"
    ? "ready"
    : r === "error"
      ? "critical"
      : r === "skipped"
        ? "attention"
        : "default";

const metadataObject = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};

const stringCandidates = (
  metadata: Record<string, unknown> | undefined,
  key: string,
) => {
  const candidates = metadataObject(metadata?.candidates);
  const values = candidates[key];
  if (!Array.isArray(values)) return [];
  return values
    .filter((value): value is string => typeof value === "string")
    .filter((value) => value.trim() !== "");
};

const candidateKeyForField = (field: string) =>
  field === "warehouse"
    ? "warehouses"
    : field === "database"
      ? "databases"
      : field === "schema"
        ? "schemas"
        : "views";

const isConfigured = (options: Record<string, string>) =>
  Object.values(options).some((value) => value.trim() !== "");

const requiredFirst = (fields: FieldDef[]) =>
  [...fields].sort(
    (a, b) => Number(Boolean(b.required)) - Number(Boolean(a.required)),
  );

const SNOWFLAKE_CORE_SCOPE = new Set(["warehouse", "database", "schema"]);

function formatWhen(value: string | null | undefined) {
  if (!value) return "not yet";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return value.slice(0, 19);
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(parsed));
}

function SnowflakeSetupHint({
  canDiscover,
  discovered,
}: {
  canDiscover: boolean;
  discovered: boolean;
}) {
  return (
    <div className="rounded-lg border border-info/40 bg-info-bg px-3 py-2">
      <div className="flex flex-wrap items-center gap-2">
        <KeyRound className="mt-0.5 h-4 w-4 shrink-0 text-brand" />
        <div className="min-w-0 flex-1">
          <div className="text-sm font-semibold text-brand">
            Read-only Snowflake role
          </div>
          <div className="mt-0.5 text-xs leading-5 text-brand">
            Key-pair or OAuth reference; no pasted private key.
          </div>
        </div>
        <Badge>Secret reference only</Badge>
        <Badge tone={canDiscover ? "ready" : "attention"}>
          {canDiscover ? "identity ready" : "identity needed"}
        </Badge>
        <Badge tone={discovered ? "ready" : "default"}>
          {discovered ? "scope discovered" : "discover next"}
        </Badge>
      </div>
    </div>
  );
}

function LatestSyncProof({
  connector,
  runnable,
  compact = false,
}: {
  connector: ConnectorView;
  runnable: boolean;
  compact?: boolean;
}) {
  const sync = connector.last_sync;
  const enabled = connector.state === "enabled";
  const ok = sync?.result === "ok";
  const failed = sync?.result === "error";
  const evidenceCount = sync?.evidence_count ?? 0;
  const tone = ok
    ? "ready"
    : failed
      ? "critical"
      : enabled
        ? "attention"
        : "default";
  const title = !runnable
    ? "Sync not available yet"
    : ok
      ? "Evidence sync complete"
      : failed
        ? "Latest sync failed"
        : enabled
          ? "Ready to sync evidence"
          : "Enable before syncing";
  const detail = !runnable
    ? "This connector is an access contract only. Probes validate configuration; a collection adapter is required before evidence sync."
    : ok
      ? `${evidenceCount} raw evidence row(s) landed. Eval schedule or dashboard control eval refreshes posture.`
      : failed
        ? (sync?.error ?? "Review the connector run log for the error.")
        : enabled
          ? "Run sync to land evidence, refresh posture, and update trust views."
          : "Test access, enable the connector, then run the first sync.";

  return (
    <section
      className={`rounded-xl border border-line bg-surface ${compact ? "p-2.5" : "p-3"}`}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold uppercase tracking-wide text-muted">
              Latest sync
            </span>
            <Badge tone={tone}>{sync?.result ?? connector.state}</Badge>
          </div>
          <div
            className={
              compact
                ? "mt-1 text-sm font-semibold text-ink"
                : "mt-2 text-base font-semibold text-ink"
            }
          >
            {title}
          </div>
          <p
            className={`mt-1 max-w-2xl text-xs text-muted ${compact ? "leading-4" : "leading-5"}`}
          >
            {detail}
          </p>
          {failed && runnable ? (
            <Link
              href="https://github.com/msaad00/trustops-security-data-lake/blob/main/docs/runbooks/OBSERVABILITY_CONNECTOR_SYNC.md"
              className="mt-2 inline-flex text-xs font-semibold text-brand hover:underline"
              target="_blank"
              rel="noreferrer"
            >
              Open connector sync runbook
            </Link>
          ) : null}
          {!runnable ? (
            <Link
              href="https://github.com/msaad00/trustops-security-data-lake/blob/main/docs/ADDING_CONNECTORS.md"
              className="mt-2 inline-flex text-xs font-semibold text-brand hover:underline"
              target="_blank"
              rel="noreferrer"
            >
              Contributor guide — add an adapter
            </Link>
          ) : null}
        </div>
      </div>
      {compact ? (
        <div className="mt-2 flex flex-wrap gap-1.5 text-xs">
          {[
            ["Evidence", sync?.evidence_count ?? "—"],
            ["Last run", formatWhen(sync?.occurred_at)],
            [
              "Duration",
              sync?.duration_ms !== null && sync?.duration_ms !== undefined
                ? `${sync.duration_ms} ms`
                : "—",
            ],
          ].map(([label, value]) => (
            <div
              key={label}
              className="rounded-full border border-line bg-panel px-2.5 py-1"
            >
              <span className="font-semibold uppercase tracking-wide text-muted">
                {label}
              </span>{" "}
              <span className="font-semibold text-ink">{value}</span>
            </div>
          ))}
        </div>
      ) : (
        <div className="mt-3 grid gap-2 sm:grid-cols-3">
          <div className="rounded-lg border border-line bg-panel p-2">
            <div className="text-[11px] font-semibold uppercase tracking-wide text-muted">
              Evidence
            </div>
            <div className="mt-1 text-sm font-semibold text-ink">
              {sync?.evidence_count ?? "—"}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel p-2">
            <div className="text-[11px] font-semibold uppercase tracking-wide text-muted">
              Last run
            </div>
            <div className="mt-1 text-sm font-semibold text-ink">
              {formatWhen(sync?.occurred_at)}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel p-2">
            <div className="text-[11px] font-semibold uppercase tracking-wide text-muted">
              Duration
            </div>
            <div className="mt-1 text-sm font-semibold text-ink">
              {sync?.duration_ms !== null && sync?.duration_ms !== undefined
                ? `${sync.duration_ms} ms`
                : "—"}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

export function ConnectorDrawer({
  connector,
  linkSessionId,
  onboarding = false,
  onClose,
  onToast,
}: Props) {
  const auditor = useAuditorMode();
  const configure = useConfigureMutation();
  const discover = useDiscoverMutation();
  const probe = useProbeMutation();
  const sync = useSyncMutation();
  const runs = useConnectorRuns(connector?.connector_id ?? null);
  const [creds, setCreds] = useState<Record<string, string>>({});
  const [options, setOptions] = useState<Record<string, string>>({});
  const [accessValidated, setAccessValidated] = useState(false);
  const [discoveryRun, setDiscoveryRun] = useState<ConnectorRun | null>(null);
  const [touchedFields, setTouchedFields] = useState<Set<string>>(new Set());
  const [connectedTab, setConnectedTab] = useState<ConnectedTab>("Overview");
  const [setupTab, setSetupTab] = useState<SetupTab>("Setup");
  const [editCloudSetup, setEditCloudSetup] = useState(false);
  const [confirmDisable, setConfirmDisable] = useState(false);
  const [savedOptionsBaseline, setSavedOptionsBaseline] = useState<
    Record<string, string>
  >({});

  const markTouched = (name: string) => {
    setTouchedFields((prev) => new Set(prev).add(name));
  };

  const credentialFieldError = (
    name: string,
    label: string,
    required?: boolean,
  ) => {
    if (!required || !touchedFields.has(name)) return null;
    if ((creds[name] ?? "").trim()) return null;
    return `${label} is required`;
  };

  useEffect(() => {
    setDiscoveryRun(null);
    setCreds({});
    setTouchedFields(new Set());
    setConnectedTab("Overview");
    setSetupTab("Setup");
    setEditCloudSetup(false);
    setConfirmDisable(false);
  }, [connector?.connector_id]);

  useEffect(() => {
    const configured = connector?.configured_options ?? {};
    const baseline = Object.fromEntries(
      Object.entries(configured)
        .filter(([key]) => key !== "raw")
        .map(([key, value]) => [key, String(value ?? "")]),
    );
    setOptions(baseline);
    setSavedOptionsBaseline(baseline);
  }, [connector?.configured_options, connector?.connector_id]);

  useEffect(() => {
    if (!connector?.connector_id || !runs.data?.length) return;
    const latestDiscover = runs.data.find(
      (run) =>
        run.kind === "discover" &&
        run.result === "ok" &&
        run.metadata &&
        typeof run.metadata === "object" &&
        Object.keys(run.metadata).length > 0,
    );
    if (latestDiscover) {
      setDiscoveryRun(latestDiscover);
    }
  }, [connector?.connector_id, runs.data]);

  if (!connector) {
    return (
      <Drawer open={false} onOpenChange={() => undefined} title="Connector">
        <></>
      </Drawer>
    );
  }

  const credentialFields = credentialFieldsFor(
    connector.connector_id,
    connector.credential_type,
  );
  const scopeFields = scopeFieldsFor(connector.connector_id);
  const schedulerFields = schedulerFieldsFor(isRunnableConnector(connector));
  const isSnowflake = connector.connector_id === "snowflake-evidence-lake";
  const usesManagedCloudLink = supportsCloudLink(connector.connector_id);
  const usesDiscoveredReadScope =
    connector.connector_id === "clickhouse-telemetry-lake" || isSnowflake;
  const isEnabled = connector.state === "enabled";
  const isRunnable = isRunnableConnector(connector);
  const hasStagedServerCredentials = Boolean(
    connector.credential_fingerprint?.trim(),
  );
  const missingCredentials = hasStagedServerCredentials
    ? []
    : credentialFields
        .filter((field) => field.required && !(creds[field.name] ?? "").trim())
        .map((field) => field.label);
  const missingScope = scopeFields
    .filter((field) => field.required && !(options[field.name] ?? "").trim())
    .map((field) => field.label);
  const missingRequired = [...missingCredentials, ...missingScope];
  const canEnable = missingRequired.length === 0 && isRunnable;
  const stagedCredentials = Object.fromEntries(
    Object.entries(creds).filter(([, value]) => value.trim() !== ""),
  );
  const stagedOptions = Object.fromEntries(
    Object.entries(options).filter(([, value]) => value.trim() !== ""),
  );
  const hasUnsavedCredentialChanges = Object.values(stagedCredentials).some(
    (value) => value.trim() !== "",
  );
  const configuredOptions = connector.configured_options ?? {};
  const savedOptions =
    Object.keys(savedOptionsBaseline).length > 0
      ? savedOptionsBaseline
      : Object.fromEntries(
          Object.entries(configuredOptions)
            .filter(([key]) => key !== "raw")
            .map(([key, value]) => [key, String(value ?? "")]),
        );
  const hasUnsavedOptionChanges = Object.entries(stagedOptions).some(
    ([key, value]) => {
      const configured = String(savedOptions[key] ?? "").trim();
      return value.trim() !== configured;
    },
  );
  const hasPendingConfigChanges =
    hasUnsavedCredentialChanges || hasUnsavedOptionChanges;
  const serverProbeValid =
    connector.last_probe?.result === "ok" &&
    hasStagedServerCredentials &&
    !hasUnsavedCredentialChanges &&
    !hasUnsavedOptionChanges;
  const probeGateSatisfied = accessValidated || serverProbeValid;
  const canTestAccess =
    isEnabled || missingRequired.length === 0 || hasStagedServerCredentials;
  const canDiscover = isEnabled || missingCredentials.length === 0;
  const discoveryMetadata = discoveryRun?.metadata;
  const showSnowflakeScopeFields =
    !isSnowflake || isEnabled || Boolean(discoveryRun) || isConfigured(options);
  const actionableMissingRequired =
    isSnowflake && !showSnowflakeScopeFields
      ? [...missingCredentials, "Discovered read scope"]
      : missingRequired;
  const coreScopeFields = isSnowflake
    ? scopeFields.filter((field) => SNOWFLAKE_CORE_SCOPE.has(field.name))
    : scopeFields;
  const advancedScopeFields = isSnowflake
    ? scopeFields.filter((field) => !SNOWFLAKE_CORE_SCOPE.has(field.name))
    : [];
  const liveDiscoveryError =
    typeof discoveryMetadata?.live_discovery_error === "string"
      ? discoveryMetadata.live_discovery_error
      : null;
  const latestError = (runs.data ?? []).find((run) => run.error);
  const latestProbeOk =
    connector.last_probe?.result === "ok" ||
    connector.last_probe?.result === "skipped" ||
    accessValidated;
  const accessReady =
    isEnabled && !hasPendingConfigChanges ? latestProbeOk : probeGateSatisfied;
  const latestSyncOk =
    connector.last_successful_sync?.result === "ok" ||
    connector.last_sync?.result === "ok";
  const scopeReady = scopeFields.length === 0 || missingScope.length === 0;
  const needsDiscovery =
    usesDiscoveredReadScope &&
    !isEnabled &&
    !discoveryRun &&
    !isConfigured(options);
  const showDiscoveryAction = !usesManagedCloudLink && needsDiscovery;
  const showConnectedCloudSummary = usesManagedCloudLink && isEnabled;
  const showingFirstTimeCloudSetup =
    usesManagedCloudLink && onboarding && !isEnabled;
  const showManagedCloudConfiguration =
    !usesManagedCloudLink ||
    (isEnabled && !showConnectedCloudSummary && !showingFirstTimeCloudSetup);
  const showCloudLinkPanel =
    usesManagedCloudLink && (!isEnabled || (isEnabled && editCloudSetup));
  const showInlineCloudSetup =
    showConnectedCloudSummary && connectedTab === "Config" && editCloudSetup;
  const integrationPreset = getIntegrationPreset(connector.connector_id);
  const showIntegrationPreset =
    Boolean(integrationPreset) &&
    !usesManagedCloudLink &&
    !showConnectedCloudSummary;
  const showSetupProgressCard = !showCloudLinkPanel;
  const compactCloudDetails = [...scopeFields, ...schedulerFields].map(
    (field) => ({
      label: field.label,
      value: options[field.name]?.trim() || field.placeholder || "default",
    }),
  );
  const runHistoryRows = runs.data ?? [];
  const operationalRuns = runHistoryRows.filter((run) =>
    ["probe", "sync", "discover"].includes(run.kind),
  );
  const configurationEvents = runHistoryRows.filter(
    (run) => !["probe", "sync", "discover"].includes(run.kind),
  );
  const setupSteps: SetupStep[] = [
    {
      label: "Authorize",
      detail:
        missingCredentials.length === 0
          ? hasStagedServerCredentials
            ? "Credentials staged on server"
            : "Identity staged"
          : `${missingCredentials.length} field(s) needed`,
      tone: missingCredentials.length === 0 ? "ready" : "attention",
    },
    {
      label: "Verify",
      detail: validateStepDetail(connector, accessReady),
      tone: accessReady ? "ready" : "default",
    },
    {
      label: "Scope",
      detail: needsDiscovery
        ? "Discover available objects"
        : scopeReady
          ? "Read scope selected"
          : `${missingScope.length} field(s) needed`,
      tone: needsDiscovery || !scopeReady ? "attention" : "ready",
    },
    {
      label: "Sync",
      detail: !isRunnable
        ? "Access contract"
        : latestSyncOk
          ? "Evidence landed"
          : isEnabled
            ? "Ready to sync"
            : "Enable first",
      tone: !isRunnable
        ? "default"
        : latestSyncOk
          ? "ready"
          : isEnabled
            ? "attention"
            : "default",
    },
  ];
  const onboardingStep =
    missingCredentials.length > 0 ? 1 : !accessReady ? 2 : !isEnabled ? 3 : 4;
  const onboardingTitle = !accessReady
    ? "Test read-only access"
    : !isEnabled
      ? "Enable this source"
      : latestSyncOk
        ? "Source connected"
        : "Land evidence into your assessment store";
  const onboardingDetail = !accessReady
    ? "Run Test connection — enable stays locked until access is verified."
    : !isEnabled
      ? "When the test passes, enable the connector to allow scheduled sync."
      : latestSyncOk
        ? "Open the dashboard to run control eval on the synced evidence."
        : "Run sync to land evidence, then evaluate controls on the dashboard.";
  const enable = async () => {
    if (!isRunnable) {
      onToast(
        "This connector is contract-only — sync adapter not shipped yet. Use Test connection to validate access.",
      );
      return;
    }
    if (!canEnable) {
      onToast(
        `Required before enabling: ${actionableMissingRequired.join(", ")}.`,
      );
      return;
    }
    if (!isEnabled && !probeGateSatisfied) {
      onToast("Test connection before enabling this connector.");
      return;
    }
    if (isEnabled && hasPendingConfigChanges && !probeGateSatisfied) {
      onToast("Test connection before saving these changes.");
      return;
    }
    const payload: ConfigurePayload = {
      state: "enabled",
      actor: "console",
      credentials: stagedCredentials,
      options: stagedOptions,
    };
    try {
      await configure.mutateAsync({ id: connector.connector_id, payload });
      setCreds({});
      setSavedOptionsBaseline(stagedOptions);
      setAccessValidated(false);
      setEditCloudSetup(false);
      if (isEnabled) {
        onToast(
          `${connector.name} changes saved — credentials redacted server-side.`,
        );
      } else {
        onToast(
          `${connector.name} enabled — credentials redacted server-side.`,
        );
      }
    } catch (err) {
      onToast(`Configure failed: ${(err as Error).message}`);
    }
  };

  const disable = async () => {
    try {
      await configure.mutateAsync({
        id: connector.connector_id,
        payload: { state: "disabled", actor: "console" },
      });
      setConfirmDisable(false);
      onToast(`${connector.name} disabled.`);
    } catch (err) {
      setConfirmDisable(false);
      onToast(`Disable failed: ${(err as Error).message}`);
    }
  };

  const runProbe = async () => {
    try {
      const payload: ProbePayload = { actor: "console" };
      if (!isEnabled || hasPendingConfigChanges) {
        payload.credentials = stagedCredentials;
        payload.options = stagedOptions;
      }
      const { run } = await probe.mutateAsync({
        id: connector.connector_id,
        payload,
      });
      const validated = run.result === "ok" || run.result === "skipped";
      setAccessValidated(validated);
      onToast(probeToastMessage(run, isEnabled));
    } catch (err) {
      setAccessValidated(false);
      onToast(`Probe failed: ${(err as Error).message}`);
    }
  };

  const runSync = async () => {
    try {
      const result = await sync.mutateAsync({
        id: connector.connector_id,
        payload: { actor: "console" },
      });
      onToast(
        result.result === "ok"
          ? result.materialized
            ? `Sync complete: ${result.evidence_count ?? 0} evidence item(s) landed and controls evaluated.`
            : `Evidence synced: ${result.evidence_count ?? 0} item(s) landed. Eval runs on schedule or from the dashboard.`
          : "Sync finished with errors; see connector runs.",
      );
    } catch (err) {
      onToast(`Sync failed: ${(err as Error).message}`);
    }
  };

  const runDiscovery = async () => {
    try {
      const payload: ProbePayload = { actor: "console" };
      if (!isEnabled) {
        payload.credentials = stagedCredentials;
        payload.options = stagedOptions;
      }
      const { run } = await discover.mutateAsync({
        id: connector.connector_id,
        payload,
      });
      setDiscoveryRun(run);
      if (
        run.result === "ok" &&
        run.metadata?.recommended_options &&
        typeof run.metadata.recommended_options === "object"
      ) {
        const recommended = Object.entries(
          run.metadata.recommended_options as Record<string, unknown>,
        ).reduce<Record<string, string>>((acc, [key, value]) => {
          if (typeof value === "string" && value.trim() !== "") {
            acc[key] = value;
          }
          return acc;
        }, {});
        if (Object.keys(recommended).length > 0) {
          setOptions((current) => ({ ...current, ...recommended }));
        }
      }
      onToast(
        run.result === "ok"
          ? "Scope discovery complete."
          : `Discovery error: ${run.error ?? "see connector runs"}`,
      );
    } catch (err) {
      setDiscoveryRun(null);
      onToast(`Discovery failed: ${(err as Error).message}`);
    }
  };

  return (
    <Drawer
      open={true}
      onOpenChange={(o) => !o && onClose()}
      title={connector.name}
      description={`${connector.category} · ${connector.collection_mode.replace("_", " ")}`}
      width="lg"
      footer={
        !auditor &&
        (!usesManagedCloudLink ||
          showManagedCloudConfiguration ||
          showConnectedCloudSummary) && (
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap gap-2">
              {showDiscoveryAction ? (
                <Button
                  variant="primary"
                  size="sm"
                  onClick={runDiscovery}
                  disabled={discover.isPending || !canDiscover}
                >
                  {discover.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Search className="h-4 w-4" />
                  )}{" "}
                  {isSnowflake ? "Discover objects" : "Discover scope"}
                </Button>
              ) : !accessReady ? (
                <Button
                  variant="primary"
                  size="sm"
                  onClick={runProbe}
                  disabled={probe.isPending || !canTestAccess}
                >
                  {probe.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <CheckCircle2 className="h-4 w-4" />
                  )}{" "}
                  Test connection
                </Button>
              ) : !isEnabled || hasPendingConfigChanges ? (
                <Button
                  variant="primary"
                  size="sm"
                  onClick={enable}
                  disabled={
                    configure.isPending ||
                    !canEnable ||
                    ((!isEnabled || hasPendingConfigChanges) &&
                      !probeGateSatisfied)
                  }
                >
                  {configure.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <PlayCircle className="h-4 w-4" />
                  )}{" "}
                  {isEnabled ? "Save changes" : "Enable connector"}
                </Button>
              ) : (
                <Button
                  variant="primary"
                  size="sm"
                  onClick={runSync}
                  disabled={sync.isPending || !isRunnable}
                >
                  {sync.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <RefreshCw className="h-4 w-4" />
                  )}{" "}
                  Sync evidence
                </Button>
              )}
              {isEnabled && !confirmDisable ? (
                <Button
                  variant="default"
                  size="sm"
                  onClick={() => setConfirmDisable(true)}
                  disabled={configure.isPending}
                >
                  <PauseCircle className="h-4 w-4" /> Disable
                </Button>
              ) : null}
              {isEnabled && confirmDisable ? (
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">
                    Disable {connector.name}?
                  </span>
                  <Button
                    variant="dark"
                    size="sm"
                    onClick={disable}
                    disabled={configure.isPending}
                  >
                    Confirm disable
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setConfirmDisable(false)}
                    disabled={configure.isPending}
                  >
                    Cancel
                  </Button>
                </div>
              ) : null}
            </div>
          </div>
        )
      }
    >
      <div className="grid gap-2 text-sm">
        {onboarding && !showingFirstTimeCloudSetup ? (
          <OnboardingGuideBanner
            step={onboardingStep}
            title={onboardingTitle}
            detail={onboardingDetail}
            dismissHref="/connectors"
          />
        ) : null}
        {usesManagedCloudLink && !showConnectedCloudSummary && (
          <div
            aria-label="Connector setup view"
            className="grid grid-cols-3 rounded-lg border border-line bg-panel p-1"
            role="tablist"
          >
            {SETUP_TABS.map((tab) => {
              const count =
                tab === "Runs"
                  ? operationalRuns.length
                  : tab === "Events"
                    ? configurationEvents.length
                    : 0;
              return (
                <button
                  key={tab}
                  type="button"
                  role="tab"
                  aria-selected={setupTab === tab}
                  className={`rounded-md px-2 py-1.5 text-xs font-semibold ${
                    setupTab === tab
                      ? "bg-surface text-ink shadow-card ring-1 ring-line"
                      : "text-muted hover:bg-surface"
                  }`}
                  onClick={() => setSetupTab(tab)}
                >
                  {tab}
                  {count > 0 ? ` · ${count}` : ""}
                </button>
              );
            })}
          </div>
        )}

        {usesManagedCloudLink &&
          !showConnectedCloudSummary &&
          setupTab === "Runs" && (
            <section className="rounded-lg border border-line bg-surface p-3">
              <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                Run history
              </div>
              <div className="mt-2 grid gap-2">
                {operationalRuns.slice(0, 8).map((run) => (
                  <div
                    key={run.occurred_at + run.kind}
                    className="rounded-lg border border-line p-2 text-xs"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span>
                        <Badge tone={toneForResult(run.result)}>
                          {run.result}
                        </Badge>{" "}
                        <Badge>{run.kind}</Badge>
                      </span>
                      <span className="text-muted">
                        {formatWhen(run.occurred_at)}
                      </span>
                    </div>
                    <div className="mt-1 text-muted">
                      {run.actor}
                      {run.duration_ms !== null && <> · {run.duration_ms} ms</>}
                      {run.evidence_count !== null && (
                        <> · {run.evidence_count} evidence</>
                      )}
                    </div>
                    {run.error && (
                      <div className="mt-1 text-danger-fg">
                        {runErrorDetail(run, connector)}
                      </div>
                    )}
                    <RunCoverageGaps run={run} />
                  </div>
                ))}
                {operationalRuns.length === 0 && (
                  <div className="text-xs text-muted">
                    No probes or syncs yet.
                  </div>
                )}
              </div>
            </section>
          )}

        {usesManagedCloudLink &&
          !showConnectedCloudSummary &&
          setupTab === "Events" && (
            <section className="rounded-lg border border-line bg-surface p-3">
              <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                Configuration events
              </div>
              <div className="mt-2 grid gap-2">
                {configurationEvents.slice(0, 8).map((event) => (
                  <div
                    key={event.occurred_at + event.kind}
                    className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-line p-2 text-xs"
                  >
                    <span>
                      <Badge>{event.kind}</Badge> <b>{event.actor}</b>
                    </span>
                    <span className="text-muted">
                      {formatWhen(event.occurred_at)}
                    </span>
                  </div>
                ))}
                {configurationEvents.length === 0 && (
                  <div className="text-xs text-muted">
                    No configuration events yet.
                  </div>
                )}
              </div>
            </section>
          )}
        {(!usesManagedCloudLink || setupTab === "Setup") && !isRunnable && (
          <section className="rounded-lg border border-warning/40 bg-warning-bg px-2.5 py-2 text-xs leading-4 text-warning-fg">
            <div className="flex items-start gap-2">
              <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <p>
                Contract only — probes validate scope; sync requires a
                collection adapter.
              </p>
            </div>
          </section>
        )}

        {(!usesManagedCloudLink ||
          showConnectedCloudSummary ||
          setupTab === "Setup") && (
          <div className="grid gap-3">
            {!auditor &&
              connector &&
              showCloudLinkPanel &&
              !showInlineCloudSetup && (
                <CloudLinkPanel
                  connector={connector}
                  linkSessionId={linkSessionId}
                  onLinked={(linked) => {
                    setAccessValidated(false);
                    setCreds((current) => ({ ...current, ...linked }));
                    setEditCloudSetup(false);
                  }}
                  onToast={onToast}
                />
              )}
            {showSetupProgressCard && (
              <section
                aria-label="Setup progress"
                className="order-first rounded-lg border border-line bg-surface p-3"
              >
                <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2">
                  <div className="flex min-w-0 items-center gap-2">
                    <ConnectorMark
                      connectorId={connector.connector_id}
                      name={connector.name}
                      category={connector.category}
                      size="sm"
                    />
                    <span className="min-w-0 text-xs font-semibold text-ink">
                      Step {Math.min(onboardingStep, 4)} of 4 ·{" "}
                      {setupSteps[Math.min(onboardingStep, 4) - 1]?.label}
                    </span>
                  </div>
                  <span className="flex flex-wrap items-center gap-1">
                    {connector.release_stage === "preview" ? (
                      <Badge
                        tone="outline"
                        title="Implemented and fixture-tested; not yet verified against a live tenant."
                      >
                        Preview
                      </Badge>
                    ) : null}
                    {connector.provenance?.source === "entry_point" ? (
                      <Badge title={connector.provenance.entry_point}>
                        Installed package
                      </Badge>
                    ) : null}
                    <Badge tone={isEnabled ? "ready" : "default"}>
                      {connector.state}
                    </Badge>
                  </span>
                </div>
                <div
                  className="mt-2 grid grid-cols-4 gap-1"
                  aria-label="Connector progress"
                >
                  {setupSteps.map((step, index) => (
                    <span
                      key={step.label}
                      title={`${step.label}: ${step.detail}`}
                      className={`h-1.5 rounded-full ${index < onboardingStep ? "bg-brand" : "bg-line"}`}
                    />
                  ))}
                </div>
                <p className="mt-2 text-xs leading-4 text-muted">
                  {setupSteps[Math.min(onboardingStep, 4) - 1]?.detail}
                </p>
              </section>
            )}
          </div>
        )}

        {showManagedCloudConfiguration &&
          !showConnectedCloudSummary &&
          (!usesManagedCloudLink || setupTab === "Setup") && (
            <details className="rounded-xl border border-line p-3">
              <summary className="flex cursor-pointer list-none items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted">
                <ListChecks className="h-3.5 w-3.5" /> Connector contract
              </summary>
              <div className="mt-3 grid gap-3 sm:grid-cols-2">
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                    Permissions
                  </div>
                  <ul className="mt-2 space-y-1 text-xs">
                    {connector.minimum_permissions.map((perm) => (
                      <li key={perm} className="flex items-start gap-2">
                        <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-success" />
                        <code className="text-ink">{perm}</code>
                      </li>
                    ))}
                  </ul>
                </div>
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                    Evidence
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {connector.evidence_types.map((t) => (
                      <Badge key={t}>{t}</Badge>
                    ))}
                  </div>
                </div>
              </div>
            </details>
          )}

        {showConnectedCloudSummary ? (
          <section className="rounded-lg border border-line p-2.5">
            <div
              aria-label="Connected connector view"
              className="grid grid-cols-3 rounded-md border border-line bg-panel p-0.5"
              role="tablist"
            >
              {CONNECTED_TABS.map((tab) => (
                <button
                  key={tab}
                  type="button"
                  role="tab"
                  aria-selected={connectedTab === tab}
                  className={`rounded px-2 py-1 text-xs font-semibold ${
                    connectedTab === tab
                      ? "bg-surface text-ink shadow-card ring-1 ring-line"
                      : "text-muted hover:bg-surface"
                  }`}
                  onClick={() => setConnectedTab(tab)}
                >
                  {tab}
                </button>
              ))}
            </div>

            {connectedTab === "Overview" && (
              <div className="mt-3 grid items-start gap-2 2xl:grid-cols-[minmax(0,1fr)_minmax(18rem,0.72fr)]">
                <LatestSyncProof
                  connector={connector}
                  runnable={isRunnable}
                  compact
                />
                <section className="rounded-xl border border-line bg-surface p-2.5">
                  <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                    Connection details
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {compactCloudDetails.map((detail) => (
                      <div
                        key={detail.label}
                        className="rounded-full border border-line bg-panel px-2.5 py-1 text-xs"
                      >
                        <span className="font-semibold uppercase tracking-wide text-muted">
                          {detail.label}
                        </span>{" "}
                        <span className="font-semibold text-ink">
                          {detail.value}
                        </span>
                      </div>
                    ))}
                  </div>
                  {connector.credential_fingerprint ? (
                    <div className="mt-2 text-xs leading-4 text-muted">
                      Credential fingerprint:{" "}
                      <code className="text-ink">
                        {connector.credential_fingerprint}
                      </code>
                      {connector.configured_at && (
                        <> · configured {formatWhen(connector.configured_at)}</>
                      )}
                    </div>
                  ) : null}
                </section>
              </div>
            )}

            {connectedTab === "Config" && (
              <div className="mt-3 grid gap-2">
                <section className="rounded-xl border border-line bg-surface p-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="min-w-0">
                      <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                        Authorization
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-1.5">
                        <Badge tone="ready">Read-only role</Badge>
                        <Badge>STS per run</Badge>
                        <Badge>Organization rollout</Badge>
                      </div>
                    </div>
                    <Button
                      type="button"
                      variant="default"
                      size="sm"
                      onClick={() => setEditCloudSetup((value) => !value)}
                    >
                      {editCloudSetup ? "Hide setup" : "Edit setup"}
                    </Button>
                  </div>
                  <p className="mt-2 text-xs leading-5 text-muted">
                    TrustOps stores the account role target and External ID.
                    Every probe, sync, and scheduled run creates a fresh AWS STS
                    assume-role session.
                  </p>
                  {hasPendingConfigChanges && (
                    <div className="mt-2 rounded-lg border border-info/40 bg-info-bg px-2.5 py-2 text-xs font-semibold text-info-fg">
                      New setup staged. Test connection, then save changes.
                    </div>
                  )}
                  <div className="mt-2 text-xs leading-5 text-muted">
                    <b className="text-ink">Current:</b> one active AWS account
                    role. <b className="text-ink">Scale:</b> deploy the same
                    read-only role with StackSets or Terraform, then import each
                    account ID or Role ARN.
                  </div>
                  {showInlineCloudSetup && !auditor && (
                    <div className="mt-2">
                      <CloudLinkPanel
                        connector={connector}
                        linkSessionId={linkSessionId}
                        onLinked={(linked) => {
                          setAccessValidated(false);
                          setCreds((current) => ({ ...current, ...linked }));
                          setEditCloudSetup(false);
                        }}
                        onToast={onToast}
                      />
                    </div>
                  )}
                </section>

                <section className="rounded-xl border border-line bg-surface p-2.5">
                  <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                    Schedule and scope
                  </div>
                  <div className="mt-2 grid gap-1.5">
                    {[...scopeFields, ...schedulerFields].map((field) => (
                      <label
                        key={field.name}
                        className="grid gap-1 text-xs font-semibold uppercase tracking-wide text-muted"
                      >
                        {field.label}
                        <input
                          value={options[field.name] ?? ""}
                          onChange={(event) => {
                            setAccessValidated(false);
                            setOptions((current) => ({
                              ...current,
                              [field.name]: event.target.value,
                            }));
                          }}
                          placeholder={field.placeholder}
                          className="rounded-lg border border-line bg-surface px-2.5 py-1.5 text-sm normal-case tracking-normal text-ink focus:outline-none focus:ring-1 focus:ring-brand"
                        />
                      </label>
                    ))}
                  </div>
                </section>

                <details className="rounded-xl border border-line bg-surface p-3 lg:col-span-2">
                  <summary className="cursor-pointer list-none text-xs font-semibold uppercase tracking-wide text-muted">
                    Granted read scope and evidence output
                  </summary>
                  <div className="mt-3 grid gap-3 lg:grid-cols-2">
                    <ul className="grid gap-2 text-xs">
                      {connector.minimum_permissions.map((perm) => (
                        <li key={perm} className="flex items-start gap-2">
                          <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-success" />
                          <code className="text-ink">{perm}</code>
                        </li>
                      ))}
                    </ul>
                    <div>
                      <p className="text-xs leading-5 text-muted">
                        Sync lands raw connector evidence. Eval produces gold
                        controls, pass/fail metrics, and proof exports.
                      </p>
                      <div className="mt-3 flex flex-wrap gap-1.5">
                        {connector.evidence_types.map((t) => (
                          <Badge key={t}>{t}</Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                </details>
              </div>
            )}

            {connectedTab === "Runs" && (
              <section className="mt-3 rounded-xl border border-line bg-surface p-3">
                <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                  Connector run log
                  {runHistoryRows.length > 8
                    ? ` · showing 8 of ${runHistoryRows.length} events`
                    : ` · ${runHistoryRows.length} event${runHistoryRows.length === 1 ? "" : "s"}`}
                </div>
                <div className="mt-3 max-h-80 overflow-auto pr-1">
                  <div className="grid gap-2">
                    {runHistoryRows.slice(0, 8).map((r) => (
                      <div
                        key={r.occurred_at + r.kind}
                        className="rounded-lg border border-line p-3 text-xs"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span>
                            <Badge tone={toneForResult(r.result)}>
                              {r.result}
                            </Badge>{" "}
                            <Badge>{r.kind}</Badge>
                          </span>
                          <span className="text-muted">
                            {formatWhen(r.occurred_at)}
                          </span>
                        </div>
                        <div className="mt-1 text-muted">
                          actor <b className="text-ink">{r.actor}</b>
                          {r.duration_ms !== null && <> · {r.duration_ms} ms</>}
                          {r.evidence_count !== null && (
                            <>
                              {" "}
                              ·{" "}
                              {r.kind === "sync"
                                ? `${r.evidence_count} evidence row(s)`
                                : `${r.evidence_count} object(s)`}
                            </>
                          )}
                        </div>
                        {r.error && (
                          <div className="mt-1 text-danger-fg">{r.error}</div>
                        )}
                        <RunCoverageGaps run={r} />
                      </div>
                    ))}
                  </div>
                </div>
              </section>
            )}
          </section>
        ) : (
          !auditor &&
          (!usesManagedCloudLink || showManagedCloudConfiguration) && (
            <details
              className="rounded-lg border border-line p-3"
              open={!usesManagedCloudLink && !showConnectedCloudSummary}
            >
              <summary className="ui-label cursor-pointer list-none">
                Scope & automation
              </summary>
              <div className="mt-3">
                {showIntegrationPreset && (
                  <div className="mt-2">
                    <IntegrationPresetPanel
                      connectorId={connector.connector_id}
                    />
                  </div>
                )}
                {connector.connector_id === "snowflake-evidence-lake" &&
                  !showIntegrationPreset && (
                    <div className="mt-2">
                      <SnowflakeSetupHint
                        canDiscover={canDiscover}
                        discovered={showSnowflakeScopeFields}
                      />
                    </div>
                  )}
                <div className="mt-2 grid gap-2">
                  {!usesManagedCloudLink && (
                    <>
                      {requiredFirst(credentialFields)
                        .filter((field) => field.required)
                        .map((field) => {
                          const error = credentialFieldError(
                            field.name,
                            field.label,
                            field.required,
                          );
                          return (
                            <label key={field.name} className="grid gap-1">
                              <span className="ui-label">{field.label}</span>
                              <input
                                type={field.secret ? "password" : "text"}
                                value={creds[field.name] ?? ""}
                                onChange={(e) => {
                                  setAccessValidated(false);
                                  setCreds((c) => ({
                                    ...c,
                                    [field.name]: e.target.value,
                                  }));
                                }}
                                onBlur={() => markTouched(field.name)}
                                aria-invalid={Boolean(error)}
                                className={`ui-input ${error ? "ui-input-error" : ""}`}
                                placeholder={field.placeholder}
                              />
                              {error ? (
                                <span className="text-xs text-danger-fg">
                                  {error}
                                </span>
                              ) : field.hint ? (
                                <span className="text-xs text-muted">
                                  {field.hint}
                                </span>
                              ) : null}
                            </label>
                          );
                        })}
                      {credentialFields.some((field) => !field.required) && (
                        <details className="rounded-lg border border-line bg-surfaceMuted p-3">
                          <summary className="cursor-pointer list-none text-xs font-semibold uppercase tracking-wide text-muted">
                            Advanced identity settings
                          </summary>
                          <div className="mt-3 grid gap-2">
                            {requiredFirst(credentialFields)
                              .filter((field) => !field.required)
                              .map((field) => (
                                <label
                                  key={field.name}
                                  className="grid gap-1 text-xs font-semibold uppercase tracking-wide text-muted"
                                >
                                  {field.label}
                                  <input
                                    type={field.secret ? "password" : "text"}
                                    value={creds[field.name] ?? ""}
                                    onChange={(e) => {
                                      setAccessValidated(false);
                                      setCreds((c) => ({
                                        ...c,
                                        [field.name]: e.target.value,
                                      }));
                                    }}
                                    className="rounded-lg border border-line bg-surface px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-brand"
                                    placeholder={field.placeholder}
                                  />
                                </label>
                              ))}
                          </div>
                        </details>
                      )}
                      {credentialFields.length === 0 && (
                        <div className="rounded-lg border border-line bg-surfaceMuted p-3 text-xs font-semibold text-muted">
                          This connector uses ambient platform credentials.
                        </div>
                      )}
                    </>
                  )}
                  {isSnowflake && !showSnowflakeScopeFields && (
                    <div className="mt-2 rounded-lg border border-line bg-surfaceMuted p-3">
                      <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                        Read scope
                      </div>
                      <div className="mt-1 text-xs font-semibold text-muted">
                        Click <b>Discover objects</b> after entering the service
                        identity. {BRAND.name} will show only Snowflake objects
                        visible to that role, then prefill the recommended read
                        scope.
                      </div>
                    </div>
                  )}
                  {scopeFields.length > 0 && showSnowflakeScopeFields && (
                    <div className="mt-2 border-t border-line pt-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div>
                          <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                            Read scope
                          </div>
                          {isSnowflake && (
                            <div className="mt-1 text-xs font-semibold text-muted">
                              Choose the warehouse, database, and schema this
                              role can read. View names are auto-filled from
                              discovery.
                            </div>
                          )}
                        </div>
                        {isSnowflake && (
                          <Badge
                            tone={
                              missingScope.length === 0 ? "ready" : "attention"
                            }
                          >
                            {missingScope.length === 0
                              ? "scope ready"
                              : `${missingScope.length} missing`}
                          </Badge>
                        )}
                      </div>
                      <div className="mt-2 grid gap-2 sm:grid-cols-2">
                        {coreScopeFields.map((field) => {
                          const candidates = stringCandidates(
                            discoveryMetadata,
                            candidateKeyForField(field.name),
                          );
                          const currentValue = options[field.name] ?? "";
                          const selectValues = currentValue
                            ? Array.from(new Set([currentValue, ...candidates]))
                            : candidates;
                          const onScopeChange = (value: string) => {
                            setAccessValidated(false);
                            setOptions((current) => {
                              const next = { ...current, [field.name]: value };
                              if (isSnowflake && field.name === "database") {
                                delete next.schema;
                                delete next.audit_events;
                                delete next.control_posture;
                                delete next.asset_risk;
                                delete next.evidence_bundles;
                              }
                              if (isSnowflake && field.name === "schema") {
                                delete next.audit_events;
                                delete next.control_posture;
                                delete next.asset_risk;
                                delete next.evidence_bundles;
                              }
                              return next;
                            });
                          };
                          return (
                            <label
                              key={field.name}
                              className="grid gap-1 text-xs font-semibold uppercase tracking-wide text-muted"
                            >
                              {field.label}
                              {isSnowflake && selectValues.length > 0 ? (
                                <select
                                  value={currentValue}
                                  onChange={(e) =>
                                    onScopeChange(e.target.value)
                                  }
                                  className="rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-brand"
                                >
                                  <option value="">
                                    Select {field.label.toLowerCase()}
                                  </option>
                                  {selectValues.map((value) => (
                                    <option key={value} value={value}>
                                      {value}
                                    </option>
                                  ))}
                                </select>
                              ) : (
                                <input
                                  value={currentValue}
                                  onChange={(e) =>
                                    onScopeChange(e.target.value)
                                  }
                                  placeholder={field.placeholder}
                                  className="rounded-lg border border-line bg-surface px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-brand"
                                />
                              )}
                            </label>
                          );
                        })}
                      </div>
                      {advancedScopeFields.length > 0 && (
                        <details className="mt-3 rounded-lg border border-line bg-surfaceMuted p-3">
                          <summary className="cursor-pointer list-none text-xs font-semibold uppercase tracking-wide text-muted">
                            Advanced view mapping
                          </summary>
                          <div className="mt-2 text-xs leading-5 text-muted">
                            Defaults work for the {BRAND.name} Snowflake schema.
                            Change these only when your evidence lake uses
                            custom view names.
                          </div>
                          <div className="mt-3 grid gap-2 sm:grid-cols-2">
                            {advancedScopeFields.map((field) => {
                              const candidates = stringCandidates(
                                discoveryMetadata,
                                candidateKeyForField(field.name),
                              );
                              const currentValue = options[field.name] ?? "";
                              const selectValues = currentValue
                                ? Array.from(
                                    new Set([currentValue, ...candidates]),
                                  )
                                : candidates;
                              const onScopeChange = (value: string) => {
                                setAccessValidated(false);
                                setOptions((current) => ({
                                  ...current,
                                  [field.name]: value,
                                }));
                              };
                              return (
                                <label
                                  key={field.name}
                                  className="grid gap-1 text-xs font-semibold uppercase tracking-wide text-muted"
                                >
                                  {field.label}
                                  {selectValues.length > 0 ? (
                                    <select
                                      value={currentValue}
                                      onChange={(e) =>
                                        onScopeChange(e.target.value)
                                      }
                                      className="rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-brand"
                                    >
                                      <option value="">
                                        Select {field.label.toLowerCase()}
                                      </option>
                                      {selectValues.map((value) => (
                                        <option key={value} value={value}>
                                          {value}
                                        </option>
                                      ))}
                                    </select>
                                  ) : (
                                    <input
                                      value={currentValue}
                                      onChange={(e) =>
                                        onScopeChange(e.target.value)
                                      }
                                      placeholder={field.placeholder}
                                      className="rounded-lg border border-line bg-surface px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-brand"
                                    />
                                  )}
                                </label>
                              );
                            })}
                          </div>
                        </details>
                      )}
                    </div>
                  )}
                  {schedulerFields.length > 0 && (
                    <div className="mt-2 border-t border-line pt-3">
                      <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                        Scheduled sync
                      </div>
                      <div className="mt-1 text-xs font-semibold text-muted">
                        Optional interval for the in-process scheduler. Leave
                        empty to sync manually from the console or API.
                      </div>
                      <div className="mt-2 grid gap-2">
                        {schedulerFields.map((field) => (
                          <label
                            key={field.name}
                            className="grid gap-1 text-xs font-semibold uppercase tracking-wide text-muted"
                          >
                            {field.label}
                            <input
                              value={options[field.name] ?? ""}
                              onChange={(e) =>
                                setOptions((current) => ({
                                  ...current,
                                  [field.name]: e.target.value,
                                }))
                              }
                              placeholder={field.placeholder}
                              className="rounded-lg border border-line bg-surface px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-brand"
                            />
                            {field.hint && (
                              <span className="font-normal normal-case tracking-normal text-muted">
                                {field.hint}
                              </span>
                            )}
                          </label>
                        ))}
                      </div>
                    </div>
                  )}
                  {usesDiscoveredReadScope && !isSnowflake && (
                    <div className="mt-2 rounded-lg border border-line bg-surfaceMuted p-3">
                      <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                        Read scope
                      </div>
                      <div className="mt-1 text-xs font-semibold text-muted">
                        Discover only the databases and tables visible to the
                        scoped read identity before this connector is enabled.
                      </div>
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        <Badge tone="info">discovered tables</Badge>
                        <Badge tone="info">least privilege</Badge>
                        <Badge tone="info">no typed scope</Badge>
                      </div>
                      {!isEnabled && (
                        <div className="mt-2 text-xs text-muted">
                          Enter the host and credential reference, test access,
                          then enable. Raw secrets are not persisted.
                        </div>
                      )}
                    </div>
                  )}
                </div>
                {!canEnable && !isEnabled && (
                  <div className="mt-2 rounded-lg border border-warning/40 bg-warning-bg px-3 py-2 text-xs font-semibold text-warning-fg">
                    Required before enabling:{" "}
                    {actionableMissingRequired.join(", ")}.
                  </div>
                )}
                {canEnable && !isEnabled && !probeGateSatisfied && (
                  <div className="mt-2 rounded-lg border border-info/40 bg-info-bg px-3 py-2 text-xs font-semibold text-info-fg">
                    {connector.connector_id === "aws-posture"
                      ? "Test connection before enabling. TrustOps will call AWS STS AssumeRole with the account target and external ID; no long-lived AWS keys are stored."
                      : connector.connector_id === "azure-posture"
                        ? "Test connection before enabling. TrustOps verifies that the configured identity can read the selected Azure subscription."
                        : isSnowflake
                          ? "Test connection before enabling. TrustOps runs a live read-only Snowflake probe."
                          : "Test connection before enabling. TrustOps validates the connector configuration and reports whether access is ready."}
                  </div>
                )}
                {discoveryRun?.metadata && (
                  <div className="mt-2 rounded-lg border border-line bg-surfaceMuted p-3 text-xs">
                    <div className="font-semibold uppercase tracking-wide text-muted">
                      Discovered scope
                    </div>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {Array.isArray(discoveryRun.metadata.selectors) &&
                        discoveryRun.metadata.selectors
                          .filter((item): item is Record<string, unknown> =>
                            Boolean(item && typeof item === "object"),
                          )
                          .slice(0, 8)
                          .map((item, index) => (
                            <Badge
                              key={`${String(item.kind)}-${String(item.name)}-${index}`}
                              tone={item.selected ? "ready" : "info"}
                            >
                              {String(item.kind)}: {String(item.name)}
                            </Badge>
                          ))}
                    </div>
                    <div className="mt-2 text-muted">
                      {liveDiscoveryError
                        ? `Live metadata was unavailable (${liveDiscoveryError}); defaults remain editable.`
                        : "Select the discovered scope, then test connection before enabling."}
                    </div>
                  </div>
                )}
                {canEnable && !isEnabled && probeGateSatisfied && (
                  <div className="mt-2 rounded-lg border border-success/40 bg-success-bg px-3 py-2 text-xs font-semibold text-success-fg">
                    Access checked. Enable writes the redacted configuration
                    event.
                  </div>
                )}
                {latestError?.error && (
                  <div className="mt-2 flex items-start gap-2 rounded-lg border border-danger/40 bg-danger-bg px-3 py-2 text-xs text-danger-fg">
                    <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    <div>
                      <b>Latest run needs attention:</b>{" "}
                      {runErrorDetail(latestError, connector)}
                    </div>
                  </div>
                )}
                {connector.credential_fingerprint ? (
                  <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-xs text-muted">
                    <div>
                      Credential fingerprint:{" "}
                      <code className="text-ink">
                        {connector.credential_fingerprint}
                      </code>
                      {connector.configured_at && (
                        <> · configured {connector.configured_at}</>
                      )}
                      {!isEnabled && (
                        <span className="block mt-1 text-warning-fg">
                          Staged but not enabled — run Test connection, then
                          Enable.
                        </span>
                      )}
                    </div>
                    {usesManagedCloudLink && !isEnabled && (
                      <Button
                        type="button"
                        variant="default"
                        size="sm"
                        onClick={() => setEditCloudSetup((value) => !value)}
                      >
                        {editCloudSetup ? "Hide setup" : "Edit setup"}
                      </Button>
                    )}
                  </div>
                ) : (
                  <div className="mt-2 text-xs text-muted">
                    No credential staged yet — complete the fields above or use
                    cloud linking.
                  </div>
                )}
              </div>
            </details>
          )
        )}
      </div>
    </Drawer>
  );
}
