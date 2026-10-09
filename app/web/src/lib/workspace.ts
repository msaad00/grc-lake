const orgName =
  process.env.NEXT_PUBLIC_GRC_LAKE_ORG_NAME?.trim() || "Workspace";
const environmentName =
  process.env.NEXT_PUBLIC_GRC_LAKE_ENVIRONMENT?.trim() || "";
const secondaryEnvironmentName =
  process.env.NEXT_PUBLIC_GRC_LAKE_SECONDARY_ENVIRONMENT?.trim() || "";

export const workspaceIdentity = {
  orgName,
  environmentName,
  secondaryEnvironmentName,
  avatar: (orgName[0] || "W").toUpperCase(),
  primaryLabel: environmentName ? `${orgName} · ${environmentName}` : orgName,
  secondaryLabel: `${orgName} — ${secondaryEnvironmentName}`,
};
