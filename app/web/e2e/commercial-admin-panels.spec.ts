import { expect, test, type Page } from "@playwright/test";

const ADMIN = {
  user_id: "u-1",
  tenant_id: "t-1",
  email: "admin@example.test",
  role: "admin",
  scopes: ["auth_admin"],
};

const ACTIVE_TOKEN = {
  id: "tok-1",
  name: "okta",
  token_prefix: "scim_ab12",
  created_by: "admin@example.test",
  created_at: "2026-09-01T12:00:00Z",
  last_used_at: null,
  revoked_at: null,
};

async function mockFeatures(
  page: Page,
  flags: { billing?: boolean; scim?: boolean; plan_usage?: boolean },
) {
  await page.route("**/api/v1/platform/features", (route) =>
    route.fulfill({
      json: {
        data: {
          commercial_hosted: true,
          plan_usage: false,
          billing: false,
          scim: false,
          ...flags,
        },
      },
    }),
  );
}

async function mockAdmin(page: Page) {
  await page.route("**/api/v1/auth/whoami", (route) =>
    route.fulfill({ json: { data: ADMIN } }),
  );
}

test("SCIM panel reveals a new token once and revokes through a confirm dialog", async ({
  page,
}) => {
  await mockAdmin(page);
  await mockFeatures(page, { scim: true });
  await page.route("**/api/v1/billing", (route) =>
    route.fulfill({
      status: 501,
      json: { error: { code: "not_implemented" } },
    }),
  );
  let tokens = [ACTIVE_TOKEN];
  await page.route("**/api/v1/platform/scim/tokens", (route) => {
    if (route.request().method() === "POST") {
      const created = { ...ACTIVE_TOKEN, id: "tok-2", name: "entra" };
      tokens = [...tokens, created];
      return route.fulfill({
        status: 201,
        json: { data: { ...created, token: "scim_plaintext_once" } },
      });
    }
    return route.fulfill({ json: { data: tokens } });
  });
  await page.route("**/api/v1/platform/scim/tokens/tok-1", (route) => {
    tokens = tokens.map((row) =>
      row.id === "tok-1" ? { ...row, revoked_at: "2026-09-02T00:00:00Z" } : row,
    );
    return route.fulfill({ status: 204, body: "" });
  });

  await page.goto("/console/auth/");
  await expect(page.getByText("SCIM provisioning")).toBeVisible();
  await expect(page.getByText("Billing", { exact: true })).toHaveCount(0);

  await page.getByRole("button", { name: "New token" }).click();
  await page.getByPlaceholder("okta").fill("entra");
  await page.getByRole("button", { name: "Create token" }).click();
  await expect(page.getByText("scim_plaintext_once")).toBeVisible();
  await page.getByRole("button", { name: "Done" }).click();
  await expect(page.getByText("scim_plaintext_once")).toHaveCount(0);

  const revoke = page.waitForRequest(
    (req) =>
      req.method() === "DELETE" && req.url().endsWith("/scim/tokens/tok-1"),
  );
  await page.getByRole("button", { name: "Revoke" }).first().click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Revoke" })
    .click();
  await revoke;
  await expect(page.getByText("1 revoked")).toBeVisible();
});

test("Billing panel shows grace state and sends admins to Stripe checkout", async ({
  page,
}) => {
  await mockAdmin(page);
  await mockFeatures(page, { billing: true });
  await page.route("**/api/v1/platform/scim/tokens", (route) =>
    route.fulfill({
      status: 501,
      json: { error: { code: "not_implemented" } },
    }),
  );
  await page.route("**/api/v1/billing", (route) =>
    route.fulfill({
      json: {
        data: {
          plan_tier: "starter",
          subscription_status: "past_due",
          access: "grace",
          customer_linked: false,
          current_period_end: null,
          cancel_at_period_end: false,
          past_due_since: "2026-09-20T00:00:00Z",
          grace_days: 7,
          self_serve_plans: ["starter", "team"],
        },
      },
    }),
  );
  await page.route("**/api/v1/billing/checkout", (route) =>
    route.fulfill({
      json: { data: { url: "/console/auth/?billing=success" } },
    }),
  );

  await page.goto("/console/auth/");
  await expect(page.getByText("Starter plan")).toBeVisible();
  await expect(page.getByText("Payment due")).toBeVisible();
  await expect(page.getByText("SCIM provisioning")).toHaveCount(0);

  const checkout = page.waitForRequest("**/api/v1/billing/checkout");
  await page.getByRole("button", { name: "Subscribe to Team" }).click();
  expect((await checkout).postDataJSON()).toEqual({ plan: "team" });
  await expect(page).toHaveURL(/billing=success/);
});

const GATED =
  /\/api\/v1\/(platform\/usage|platform\/scim\/tokens|billing)(\?|$)/;

test("an OSS server probes features once and never calls the gated routes", async ({
  page,
}) => {
  const gated: string[] = [];
  const errors: string[] = [];
  page.on("request", (req) => {
    if (GATED.test(req.url())) gated.push(req.url());
  });
  page.on("console", (msg) => {
    if (msg.type() === "error") errors.push(msg.text());
  });
  const probe = page.waitForResponse(/\/api\/v1\/platform\/features$/);
  await page.goto("/console/auth/");
  expect((await probe).status()).toBe(200);
  await expect(page.getByText("Current session")).toBeVisible();
  await page.waitForLoadState("networkidle");
  expect(gated).toEqual([]);
  expect(errors).toEqual([]);
  await expect(page.getByText("Hosted plan usage")).toHaveCount(0);
  await expect(page.getByText("SCIM provisioning")).toHaveCount(0);
});

test("a server without the feature probe still hides 501 panels", async ({
  page,
}) => {
  await mockAdmin(page);
  await page.route("**/api/v1/platform/features", (route) =>
    route.fulfill({ status: 404, json: { detail: "Not Found" } }),
  );
  for (const path of ["platform/usage", "platform/scim/tokens", "billing"])
    await page.route(`**/api/v1/${path}`, (route) =>
      route.fulfill({ status: 501, json: { detail: "not enabled" } }),
    );
  await page.goto("/console/auth/");
  await expect(page.getByText("Current session")).toBeVisible();
  await expect(page.getByText("Hosted plan usage")).toHaveCount(0);
  await expect(page.getByText("SCIM provisioning")).toHaveCount(0);
  await expect(page.getByText("Billing", { exact: true })).toHaveCount(0);
  await expect(
    page.getByText(
      /Some requests were rejected|Can.t reach the assessment API/,
    ),
  ).toHaveCount(0);
});
