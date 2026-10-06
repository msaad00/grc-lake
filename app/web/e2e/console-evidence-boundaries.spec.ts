import { test, expect } from "@playwright/test";

test("auditor view survives navigation and reload", async ({ page }) => {
  await page.goto("/console/dashboard/?role=auditor");
  await expect(page.getByText(/Auditor view/i).first()).toBeVisible();
  await page
    .getByRole("link", { name: "Controls", exact: true })
    .first()
    .click();
  await page.reload();
  await expect(page.getByText(/Auditor view/i).first()).toBeVisible();
});

test("permission failures explain access instead of reporting an outage", async ({
  page,
}) => {
  await page.route("**/api/v1/controls?*", (route) =>
    route.fulfill({
      status: 403,
      contentType: "application/json",
      body: JSON.stringify({ errors: [{ detail: "requires scope: read" }] }),
    }),
  );
  await page.goto("/console/controls/");
  await expect(
    page.getByRole("alert").filter({ hasText: /permission/i }),
  ).toBeVisible();
  await expect(
    page.getByRole("alert").filter({ hasText: /API is unavailable/i }),
  ).toHaveCount(0);
});

test("account menu does not invent deployment environments", async ({
  page,
}) => {
  await page.goto("/console/dashboard/");
  await page.getByRole("button", { name: /account menu/i }).click();
  await expect(page.getByRole("menu")).not.toContainText("Staging");
  await expect(page.getByRole("menu")).not.toContainText("Production");
});

test("date-only values preserve the selected US calendar day", async () => {
  const { formatDate } = await import("../src/lib/format");
  const previous = process.env.TZ;
  try {
    process.env.TZ = "America/Los_Angeles";
    expect(formatDate("2026-10-06")).toBe("Oct 6, 2026");
  } finally {
    process.env.TZ = previous;
  }
});

test("system dark theme and route titles are respected", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("/console/dashboard/");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page).toHaveTitle("Overview · TrustOps");
  await page
    .getByRole("link", { name: "Controls", exact: true })
    .first()
    .click();
  await expect(page).toHaveTitle("Controls · TrustOps");
});
