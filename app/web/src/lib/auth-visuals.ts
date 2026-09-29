/**
 * Neutral identity-provider marks for login and access surfaces.
 * Text abbreviations with recognizable accent colors — not official logos.
 */

export interface AuthVisual {
  mark: string;
  accent: string;
  bg: string;
  protocol: string;
}

export const AUTH_VISUALS: Record<string, AuthVisual> = {
  okta: { mark: "OKTA", accent: "#006BA6", bg: "#eff6ff", protocol: "OIDC" },
  azure_ad: {
    mark: "Entra",
    accent: "#0066B5",
    bg: "#eff6ff",
    protocol: "OIDC",
  },
  google: { mark: "G", accent: "#1D5FCC", bg: "#eff6ff", protocol: "OIDC" },
  auth0: { mark: "A0", accent: "#C2410C", bg: "#fff7ed", protocol: "OIDC" },
  onelogin: { mark: "1L", accent: "#1F1F1F", bg: "#f1f5f9", protocol: "OIDC" },
  generic_oidc: {
    mark: "OIDC",
    accent: "#2563eb",
    bg: "#eff6ff",
    protocol: "OIDC",
  },
  okta_saml: {
    mark: "OKTA",
    accent: "#006BA6",
    bg: "#eff6ff",
    protocol: "SAML",
  },
  azure_ad_saml: {
    mark: "Entra",
    accent: "#0066B5",
    bg: "#eff6ff",
    protocol: "SAML",
  },
  google_saml: {
    mark: "G",
    accent: "#1D5FCC",
    bg: "#eff6ff",
    protocol: "SAML",
  },
  onelogin_saml: {
    mark: "1L",
    accent: "#1F1F1F",
    bg: "#f1f5f9",
    protocol: "SAML",
  },
  generic_saml: {
    mark: "SAML",
    accent: "#7c3aed",
    bg: "#f5f3ff",
    protocol: "SAML",
  },
  api_key: {
    mark: "KEY",
    accent: "#047857",
    bg: "#ecfdf5",
    protocol: "API key",
  },
  oidc: { mark: "OIDC", accent: "#2563eb", bg: "#eff6ff", protocol: "OIDC" },
  saml: { mark: "SAML", accent: "#7c3aed", bg: "#f5f3ff", protocol: "SAML" },
};

export function authVisual(
  providerKind: string | undefined,
  methodId?: string,
): AuthVisual {
  if (providerKind && AUTH_VISUALS[providerKind]) {
    return AUTH_VISUALS[providerKind];
  }
  if (methodId && AUTH_VISUALS[methodId]) {
    return AUTH_VISUALS[methodId];
  }
  return AUTH_VISUALS.generic_oidc;
}
