/** Hosted-mode presentation for connector credential references. */

import {
  TENANT_PREFIX_PLACEHOLDER,
  type CredentialPolicy,
} from "@/lib/cloud-link-validation";
import type { ConnectorFieldDef } from "@/lib/connector-forms";

const ENV_NAME_PLACEHOLDER = /^[A-Z][A-Z0-9_<>]*$/;
const REF_NAME = /_(ref|env)$/;
const REF_LABEL = /\b(reference|env var|env)\b/i;
const EXISTING_PREFIX =
  /^(?:GRC_LAKE|TRUSTOPS)_TENANT_.*?__|^(?:GRC_LAKE|TRUSTOPS)_/;

/** A field whose value names an environment variable (mirrors REF_KEY_SUFFIXES). */
export function isSecretRefField(field: ConnectorFieldDef): boolean {
  if (!ENV_NAME_PLACEHOLDER.test(field.placeholder)) return false;
  return REF_NAME.test(field.name) || REF_LABEL.test(field.label);
}

/** An example env-var name the hosted secret-ref policy accepts. */
export function hostedRefPlaceholder(
  placeholder: string,
  prefix: string | null,
): string {
  const tenantPrefix = prefix ?? TENANT_PREFIX_PLACEHOLDER;
  const bare = placeholder
    .replace(TENANT_PREFIX_PLACEHOLDER, "")
    .replace(EXISTING_PREFIX, "");
  return `${tenantPrefix}${bare}`;
}

/** Rewrite reference placeholders and hints for hosted mode; local fields are unchanged. */
export function hostedCredentialFields(
  fields: ConnectorFieldDef[],
  policy: CredentialPolicy,
): ConnectorFieldDef[] {
  if (!policy.hosted) return fields;
  const prefix = policy.secretRefPrefix ?? TENANT_PREFIX_PLACEHOLDER;
  return fields.map((field) =>
    isSecretRefField(field)
      ? {
          ...field,
          placeholder: hostedRefPlaceholder(field.placeholder, prefix),
          hint: `${field.hint ? `${field.hint} ` : ""}Hosted: name it under ${prefix}, or use a name your operator allowlists.`,
        }
      : field,
  );
}
