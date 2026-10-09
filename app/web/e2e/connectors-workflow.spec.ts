import { test, expect } from "@playwright/test";

const CONNECTOR_ID = "github-security";

async function ensureConnectorDisabled(
  request: import("@playwright/test").APIRequestContext,
) {
  const response = await request.get("/api/v1/connectors");
  expect(response.ok()).toBeTruthy();
  const connectors = (await response.json()).data ?? [];
  const connector = connectors.find(
    (item: { connector_id?: string }) => item.connector_id === CONNECTOR_ID,
  );
  if (connector?.state !== "enabled") return;
  const disable = await request.post(
    `/api/v1/connectors/${CONNECTOR_ID}/configure`,
    { data: { state: "disabled", actor: "e2e" } },
  );
  expect(disable.ok()).toBeTruthy();
}

async function ensureConnectorEnabled(
  request: import("@playwright/test").APIRequestContext,
) {
  const current = await request.get("/api/v1/connectors");
  expect(current.ok()).toBeTruthy();
  const connectors = (await current.json()).data ?? [];
  const connector = connectors.find(
    (item: { connector_id?: string }) => item.connector_id === CONNECTOR_ID,
  );
  if (connector?.state === "enabled") return;

  const access = {
    credentials: { token: "e2e-token" },
    options: { repo: "acme/platform" },
  };
  const probe = await request.post(`/api/v1/connectors/${CONNECTOR_ID}/probe`, {
    data: { actor: "e2e", ...access },
  });
  expect(probe.ok()).toBeTruthy();

  const response = await request.post(
    `/api/v1/connectors/${CONNECTOR_ID}/configure`,
    {
      data: {
        state: "enabled",
        actor: "e2e",
        ...access,
      },
    },
  );
  expect(response.ok()).toBeTruthy();
}

test.describe("connectors workflow", () => {
  test("AWS starts as a compact authorization workspace", async ({
    page,
    request,
  }) => {
    await request.post("/api/v1/connectors/aws-posture/configure", {
      data: { state: "disabled", actor: "e2e" },
    });
    await page.goto("/console/connectors/?connect=aws-posture");

    const dialog = page.getByRole("dialog");
    await expect(
      dialog.getByRole("heading", { name: "AWS Posture" }),
    ).toBeVisible({ timeout: 15_000 });
    const activeAuthorization = dialog.getByRole("button", {
      name: /Connect cloud account|Test connection/,
    });
    await expect(activeAuthorization).toHaveCount(1);
    await expect(activeAuthorization).toBeVisible();
    await expect(dialog.getByText("Scheduled sync")).toBeHidden();

    const box = await activeAuthorization.boundingBox();
    expect(box).not.toBeNull();
    expect((box?.y ?? 0) + (box?.height ?? 0)).toBeLessThanOrEqual(720);
  });

  test("probe-gated enable flow for github-security", async ({
    page,
    request,
  }) => {
    await ensureConnectorDisabled(request);

    await page.goto(`/console/connectors/?connect=${CONNECTOR_ID}`);
    await expect(page.getByRole("main")).toBeVisible({ timeout: 20_000 });

    await expect(
      page
        .getByRole("dialog")
        .getByRole("heading", { name: "GitHub Security" }),
    ).toBeVisible({ timeout: 15_000 });

    // Server mode resolves only tenant-prefixed (or operator-allowlisted) refs;
    // the no-auth e2e server acts for the synthetic "insecure" tenant.
    await page
      .getByLabel(/GitHub App installation token env/i)
      .fill("GRC_LAKE_TENANT_INSECURE__GITHUB_TOKEN");
    await page.getByLabel(/Repository \(owner\/name\)/i).fill("acme/platform");

    const dialog = page.getByRole("dialog");
    await expect(
      dialog.getByRole("button", { name: "Enable connector" }),
    ).toHaveCount(0);

    await dialog.getByRole("button", { name: "Test connection" }).click();
    const enableBtn = dialog.getByRole("button", {
      name: "Enable connector",
    });
    await expect(enableBtn).toBeEnabled({ timeout: 15_000 });

    await enableBtn.click();
    await expect(page.getByText(/GitHub Security enabled/i)).toBeVisible({
      timeout: 15_000,
    });
    await expect(
      dialog.getByRole("button", { name: "Sync evidence" }),
    ).toBeVisible();

    const listResponse = await request.get("/api/v1/connectors");
    expect(listResponse.ok()).toBeTruthy();
    const connectors = (await listResponse.json()).data ?? [];
    const enabled = connectors.find(
      (item: { connector_id?: string }) => item.connector_id === CONNECTOR_ID,
    );
    expect(enabled?.state).toBe("enabled");
  });

  test("disable requires confirmation and cancel leaves the connector enabled", async ({
    page,
    request,
  }) => {
    await ensureConnectorEnabled(request);
    await page.goto(`/console/connectors/?connect=${CONNECTOR_ID}`);

    const dialog = page.getByRole("dialog");
    await expect(
      dialog.getByRole("heading", { name: "GitHub Security" }),
    ).toBeVisible({ timeout: 15_000 });

    await dialog.getByRole("button", { name: "Disable", exact: true }).click();
    await expect(
      dialog.getByRole("button", { name: "Confirm disable" }),
    ).toBeVisible();
    await expect(
      dialog.getByText("Disable GitHub Security?", { exact: true }),
    ).toBeVisible();

    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(
      dialog.getByRole("button", { name: "Confirm disable" }),
    ).toHaveCount(0);

    const stillEnabled = await request.get("/api/v1/connectors");
    const enabledConnectors = (await stillEnabled.json()).data ?? [];
    expect(
      enabledConnectors.find(
        (item: { connector_id?: string }) => item.connector_id === CONNECTOR_ID,
      )?.state,
    ).toBe("enabled");

    await dialog.getByRole("button", { name: "Disable", exact: true }).click();
    await dialog.getByRole("button", { name: "Confirm disable" }).click();
    await expect(page.getByText(/GitHub Security disabled/i)).toBeVisible({
      timeout: 15_000,
    });

    const disabledResponse = await request.get("/api/v1/connectors");
    const disabledConnectors = (await disabledResponse.json()).data ?? [];
    expect(
      disabledConnectors.find(
        (item: { connector_id?: string }) => item.connector_id === CONNECTOR_ID,
      )?.state,
    ).toBe("disabled");
  });

  test("control eval runs from dashboard sources view", async ({ page }) => {
    await page.goto("/console/dashboard/");
    await expect(page.getByRole("main")).toBeVisible({ timeout: 20_000 });
    await expect(
      page.getByRole("tab", { name: "Frameworks", exact: true }),
    ).toHaveAttribute("aria-selected", "true");

    await page.getByRole("tab", { name: "Sources", exact: true }).click();
    await expect(
      page.getByRole("tab", { name: "Sources", exact: true }),
    ).toHaveAttribute("aria-selected", "true");
    await page.getByRole("button", { name: "Run control eval" }).click();
    await expect(
      page.getByText(
        /Control eval complete|Control eval failed|Control eval finished/i,
      ),
    ).toBeVisible({
      timeout: 30_000,
    });
  });
});
