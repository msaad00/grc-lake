import { expect, test } from "@playwright/test";

test("read-only risk actions are disabled with an inline explanation", async ({
  page,
}) => {
  await page.route("**/api/v1/auth/whoami", (r) =>
    r.fulfill({
      json: {
        data: {
          user_id: "reader",
          tenant_id: "t",
          email: "reader@example.test",
          role: "read_only",
          scopes: ["read"],
        },
      },
    }),
  );
  await page.route("**/api/v1/risks*", (r) =>
    r.fulfill({
      json: {
        data: [
          {
            id: "risk1",
            title: "Existing risk",
            severity: "low",
            likelihood: "low",
            impact: "low",
            status: "open",
          },
        ],
      },
    }),
  );
  await page.goto("/console/risks/");
  await page.getByPlaceholder("Risk title").fill("Cannot write");
  await expect(
    page.getByRole("button", { name: "Add risk", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Delete", exact: true }),
  ).toBeDisabled();
  await expect(page.getByText(/Your role can view risks/)).toBeVisible();
});

test("users role select has an accessible name", async ({ page }) => {
  await page.route("**/api/v1/auth/whoami", (r) =>
    r.fulfill({
      json: {
        data: {
          user_id: "admin",
          email: "admin@example.test",
          role: "admin",
          scopes: ["auth_admin"],
        },
      },
    }),
  );
  await page.route("**/api/v1/auth/users", (r) =>
    r.fulfill({
      json: {
        data: [
          {
            id: "other",
            email: "member@example.test",
            role: "read_only",
            is_active: true,
          },
        ],
      },
    }),
  );
  await page.goto("/console/auth/");
  await expect(
    page.getByRole("combobox", { name: "Role for member@example.test" }),
  ).toBeVisible();
});

test("remediation due dates keep their UTC calendar day in Los Angeles", async ({
  browser,
}) => {
  const context = await browser.newContext({
    timezoneId: "America/Los_Angeles",
  });
  const page = await context.newPage();
  try {
    await page.route("**/api/v1/remediation/tasks*", (r) =>
      r.fulfill({
        json: {
          data: [
            {
              id: "task1",
              title: "Calendar boundary",
              status: "open",
              priority: "low",
              owner: "owner",
              due_at: "2026-10-06T00:00:00Z",
            },
          ],
        },
      }),
    );
    await page.goto("/console/remediation/");
    await expect(page.getByText(/due Oct 6, 2026/)).toBeVisible();
  } finally {
    await context.close();
  }
});
