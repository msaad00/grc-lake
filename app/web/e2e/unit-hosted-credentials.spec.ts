import { expect, test } from "@playwright/test";
import {
  azureDelegationError,
  gcpImpersonationError,
  secretRefError,
} from "../src/lib/cloud-link-validation";
import {
  hostedCredentialFields,
  hostedRefPlaceholder,
  isSecretRefField,
} from "../src/lib/hosted-credentials";
import type { ConnectorFieldDef } from "../src/lib/connector-forms";

// Pure-function checks for the hosted credential helpers; no browser page needed.

const PREFIX = "TRUSTOPS_TENANT_ACME__";
const HOSTED = { hosted: true, secretRefPrefix: PREFIX };
const LOCAL = { hosted: false, secretRefPrefix: null };
const CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const ENTRA = "99999999-8888-7777-6666-555555555555";

test.describe("hosted ref placeholders", () => {
  test("rewrites env-var names under the tenant prefix", () => {
    expect(hostedRefPlaceholder("TRUSTOPS_CLICKHOUSE_TOKEN", PREFIX)).toBe(
      "TRUSTOPS_TENANT_ACME__CLICKHOUSE_TOKEN",
    );
    expect(hostedRefPlaceholder("JAMF_CLIENT_SECRET", PREFIX)).toBe(
      "TRUSTOPS_TENANT_ACME__JAMF_CLIENT_SECRET",
    );
    expect(
      hostedRefPlaceholder("TRUSTOPS_TENANT_<ID>__AZURE_CLIENT_SECRET", PREFIX),
    ).toBe("TRUSTOPS_TENANT_ACME__AZURE_CLIENT_SECRET");
    expect(hostedRefPlaceholder("TRUSTOPS_API_TOKEN", null)).toBe(
      "TRUSTOPS_TENANT_<ID>__API_TOKEN",
    );
  });

  test("only reference fields are treated as env-var names", () => {
    const ref: ConnectorFieldDef = {
      name: "credential_ref",
      label: "Scoped credential reference",
      placeholder: "TRUSTOPS_SIEM_TOKEN",
    };
    const legacyRef: ConnectorFieldDef = {
      name: "api_key",
      label: "API key reference",
      placeholder: "TRUSTOPS_API_KEY",
    };
    const warehouse: ConnectorFieldDef = {
      name: "warehouse",
      label: "Warehouse",
      placeholder: "TRUSTOPS_READ_WH",
    };
    const role: ConnectorFieldDef = {
      name: "role",
      label: "Read-only role (optional)",
      placeholder: "TRUSTOPS_READER",
    };
    expect(isSecretRefField(ref)).toBe(true);
    expect(isSecretRefField(legacyRef)).toBe(true);
    expect(isSecretRefField(warehouse)).toBe(false);
    expect(isSecretRefField(role)).toBe(false);

    const hosted = hostedCredentialFields([ref, warehouse], HOSTED);
    expect(hosted[0].placeholder).toBe("TRUSTOPS_TENANT_ACME__SIEM_TOKEN");
    expect(hosted[0].hint).toContain(PREFIX);
    expect(hosted[1]).toEqual(warehouse);
    expect(hostedCredentialFields([ref], LOCAL)[0]).toEqual(ref);
  });
});

test.describe("hosted secret reference validation", () => {
  test("accepts only env-var names and refuses server secrets when hosted", () => {
    expect(secretRefError("", HOSTED)).toMatch(
      /Enter the environment variable/,
    );
    expect(secretRefError("s3cr3t value==", HOSTED)).toMatch(
      /environment variable name/,
    );
    expect(secretRefError("AZURE_CLIENT_SECRET", HOSTED)).toContain(PREFIX);
    expect(secretRefError("TRUSTOPS_OTHER", HOSTED)).toContain(PREFIX);
    expect(
      secretRefError("TRUSTOPS_TENANT_OTHER__AZURE_CLIENT_SECRET", HOSTED),
    ).toContain(PREFIX);
    expect(secretRefError(`${PREFIX}AZURE_CLIENT_SECRET`, HOSTED)).toBeNull();
    // Operator allowlists are server-side; a non-reserved name is not blocked.
    expect(secretRefError("ACME_VAULT_AZURE_SECRET", HOSTED)).toBeNull();
    expect(secretRefError("AZURE_CLIENT_SECRET", LOCAL)).toBeNull();
  });

  test("mirrors the Azure app registration rules", () => {
    const valid = {
      tenantId: ENTRA,
      clientId: CLIENT_ID,
      secretRef: `${PREFIX}AZURE_CLIENT_SECRET`,
    };
    expect(azureDelegationError(valid, HOSTED)).toBeNull();
    expect(azureDelegationError({ ...valid, tenantId: "" }, HOSTED)).toMatch(
      /tenant ID/,
    );
    expect(
      azureDelegationError({ ...valid, tenantId: "bad tenant!" }, HOSTED),
    ).toMatch(/tenant ID/);
    expect(
      azureDelegationError(
        { ...valid, tenantId: "contoso.onmicrosoft.com" },
        HOSTED,
      ),
    ).toBeNull();
    expect(
      azureDelegationError({ ...valid, clientId: "not-a-guid" }, HOSTED),
    ).toMatch(/client ID/);
    expect(
      azureDelegationError({ ...valid, secretRef: "AZURE_SECRET" }, HOSTED),
    ).toContain(PREFIX);
    expect(
      azureDelegationError(
        { tenantId: "", clientId: "", secretRef: "" },
        LOCAL,
      ),
    ).toBeNull();
  });

  test("mirrors the GCP impersonation rules", () => {
    expect(gcpImpersonationError("", HOSTED)).toMatch(/service account/);
    expect(gcpImpersonationError("someone@gmail.com", HOSTED)).toMatch(
      /iam.gserviceaccount.com/,
    );
    expect(
      gcpImpersonationError(
        "trustops-reader@customer-proj.iam.gserviceaccount.com",
        HOSTED,
      ),
    ).toBeNull();
    expect(gcpImpersonationError("", LOCAL)).toBeNull();
  });
});
