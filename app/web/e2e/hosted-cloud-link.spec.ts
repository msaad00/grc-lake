import { expect, test, type APIRequestContext } from "@playwright/test";

// The e2e server runs in server mode without auth, acting for the synthetic
// "insecure" tenant: cloud links must name tenant-delegated access and secret
// references must sit under that tenant's prefix.
const PREFIX = "GRC_LAKE_TENANT_INSECURE__";
const SUBSCRIPTION = "11111111-2222-3333-4444-555555555555";
const ENTRA_TENANT = "99999999-8888-7777-6666-555555555555";
const CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const SERVICE_ACCOUNT = "trustops-reader@customer-proj.iam.gserviceaccount.com";

async function resetConnector(request: APIRequestContext, id: string) {
  await request.post(`/api/v1/connectors/${id}/configure`, {
    data: { state: "disabled", actor: "e2e" },
  });
}

test.describe("hosted cloud link", () => {
  test("whoami reports the hosted credential policy", async ({ request }) => {
    const body = await (await request.get("/api/v1/auth/whoami")).json();
    expect(body.data.hosted).toBe(true);
    expect(body.data.secret_ref_prefix).toBe(PREFIX);
  });

  test("Azure collects the tenant app registration by keyboard", async ({
    page,
    request,
  }) => {
    await resetConnector(request, "azure-posture");
    await page.goto("/console/connectors/?connect=azure-posture");
    const dialog = page.getByRole("dialog");
    await dialog
      .getByRole("button", { name: "Connect cloud account" })
      .click({ timeout: 15_000 });

    const registration = dialog.getByRole("group", {
      name: "Your Entra app registration",
    });
    await expect(registration).toBeVisible();
    await expect(
      dialog.getByText(/never reads Azure as its own/),
    ).toBeVisible();
    await expect(
      dialog.getByRole("button", { name: "Grant Azure admin consent" }),
    ).toHaveCount(0);

    const refInput = registration.getByLabel("Environment variable name");
    await expect(refInput).toHaveAttribute(
      "placeholder",
      `${PREFIX}AZURE_CLIENT_SECRET`,
    );
    await expect(registration).toContainText(PREFIX);

    // Keyboard only: type into each field and Tab to the next one.
    await dialog.getByLabel("Azure subscription ID").fill(SUBSCRIPTION);
    await registration.getByLabel("Entra tenant ID").focus();
    await page.keyboard.type(ENTRA_TENANT);
    await page.keyboard.press("Tab");
    await expect(
      registration.getByLabel("Application (client) ID"),
    ).toBeFocused();
    await page.keyboard.type(CLIENT_ID);
    await page.keyboard.press("Tab");
    await expect(registration.getByLabel("Credential type")).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(refInput).toBeFocused();
    await page.keyboard.type("AZURE_CLIENT_SECRET");
    await page.keyboard.press("Tab");

    const next = dialog.getByRole("button", { name: "Next: verify access" });
    await expect(dialog.getByRole("alert")).toContainText(PREFIX);
    await expect(next).toBeDisabled();

    await refInput.fill("super secret value==");
    await expect(dialog.getByRole("alert")).toContainText(
      "never paste the secret",
    );
    await expect(next).toBeDisabled();

    await registration
      .getByLabel("Credential type")
      .selectOption("client_certificate_ref");
    await expect(refInput).toHaveAttribute(
      "placeholder",
      `${PREFIX}AZURE_CLIENT_CERT`,
    );
    await refInput.fill(`${PREFIX}AZURE_CLIENT_CERT`);
    await expect(dialog.getByRole("alert")).toHaveCount(0);
    await expect(next).toBeEnabled();

    const [linkRequest, linkResponse] = await Promise.all([
      page.waitForRequest((req) => /\/link\/complete$/.test(req.url())),
      page.waitForResponse((res) => /\/link\/complete$/.test(res.url())),
      next.click(),
    ]);
    expect(linkRequest.postDataJSON().delegation).toEqual({
      tenant_id: ENTRA_TENANT,
      client_id: CLIENT_ID,
      client_certificate_ref: `${PREFIX}AZURE_CLIENT_CERT`,
    });
    expect(linkResponse.status()).toBe(201);
    const staged = (await linkResponse.json()).data.configure;
    expect(staged.credentials).toMatchObject({
      subscription_id: SUBSCRIPTION,
      tenant_id: ENTRA_TENANT,
      client_id: CLIENT_ID,
      client_certificate_ref: `${PREFIX}AZURE_CLIENT_CERT`,
    });
    expect(staged.options?.azure_tenant_id).toBeUndefined();
    await expect(page.getByText(/Credentials staged/)).toBeVisible();
  });

  test("GCP collects the impersonation target", async ({ page, request }) => {
    await resetConnector(request, "gcp-posture");
    await page.goto("/console/connectors/?connect=gcp-posture");
    const dialog = page.getByRole("dialog");
    await dialog
      .getByRole("button", { name: "Connect cloud account" })
      .click({ timeout: 15_000 });

    await expect(dialog.getByText(/GRC_LAKE_GCP_WIF_MEMBER/)).toHaveCount(0);
    await dialog.getByLabel("GCP project ID").fill("customer-proj");
    const target = dialog.getByLabel("Service account to impersonate");
    await target.fill("someone@gmail.com");
    await target.blur();
    const next = dialog.getByRole("button", { name: "Next: verify access" });
    await expect(dialog.getByRole("alert")).toContainText(
      ".iam.gserviceaccount.com",
    );
    await expect(next).toBeDisabled();

    await target.fill(SERVICE_ACCOUNT);
    await expect(next).toBeEnabled();
    const [linkResponse] = await Promise.all([
      page.waitForResponse((res) => /\/link\/complete$/.test(res.url())),
      next.click(),
    ]);
    expect(linkResponse.status()).toBe(201);
    expect((await linkResponse.json()).data.configure.credentials).toEqual({
      project_id: "customer-proj",
      impersonate_service_account: SERVICE_ACCOUNT,
    });
  });

  test("the hosted Azure form fits a 390px screen", async ({
    page,
    request,
  }) => {
    await resetConnector(request, "azure-posture");
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/console/connectors/?connect=azure-posture");
    const dialog = page.getByRole("dialog");
    await dialog
      .getByRole("button", { name: "Connect cloud account" })
      .click({ timeout: 15_000 });
    const registration = dialog.getByRole("group", {
      name: "Your Entra app registration",
    });
    await registration.scrollIntoViewIfNeeded();
    const box = await registration.boundingBox();
    const drawer = await dialog.boundingBox();
    expect(box!.x).toBeGreaterThanOrEqual(drawer!.x);
    expect(box!.x + box!.width).toBeLessThanOrEqual(
      drawer!.x + drawer!.width + 1,
    );
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
  });

  test("connector forms suggest tenant-prefixed reference names", async ({
    page,
  }) => {
    await page.goto("/console/connectors/?connect=github-security");
    const field = page
      .getByRole("dialog")
      .getByLabel(/GitHub App installation token env/i);
    await expect(field).toHaveAttribute(
      "placeholder",
      `${PREFIX}GITHUB_APP_INSTALLATION_TOKEN`,
      { timeout: 15_000 },
    );
  });
});
