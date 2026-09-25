import { expect, test, type Page } from "@playwright/test";

const REVIEWED_ARTICLE = {
  article_id: "CC6.1",
  title: "Logical access security",
  official_source_url: "https://example.test/soc2",
  reviewed_by: "internal-trust-team",
  reviewed_at: "2026-06-30T00:00:00Z",
  rationale: "Reviewed mapping.",
};

const MAPPINGS = [
  {
    control_id: "SOC2-CC6.1",
    framework_id: "soc2",
    articles: [REVIEWED_ARTICLE],
  },
  {
    control_id: "CIS-AWS-1.1",
    framework_id: "cis_aws",
    articles: [
      {
        ...REVIEWED_ARTICLE,
        article_id: "1.1",
        title: "Maintain current contact details",
        review_status: "proposed",
      },
    ],
  },
  {
    control_id: "CIS-AWS-1.2",
    framework_id: "cis_aws",
    articles: [
      {
        ...REVIEWED_ARTICLE,
        article_id: "1.2",
        title: "Security contact information",
        review_status: "proposed",
      },
    ],
  },
];

async function mockMappings(page: Page) {
  await page.route(
    (url) => url.pathname === "/api/v1/mappings",
    (route) =>
      route.fulfill({
        json: { data: MAPPINGS, meta: { count: MAPPINGS.length } },
      }),
  );
}

test("crosswalk counts only reviewed mappings and badges proposed rows", async ({
  page,
}) => {
  await mockMappings(page);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/console/crosswalk/");

  await expect(page.getByText("Links: 1 reviewed · 2 proposed")).toBeVisible({
    timeout: 20_000,
  });
  await expect(page.getByText(/\d+ reviewed mappings/)).toHaveCount(0);
  await expect(
    page.getByText("Control mappings", { exact: true }),
  ).toBeVisible();

  const table = page.locator("table").first();
  await expect(table.getByText("proposed", { exact: true })).toHaveCount(2);
  await expect(table.getByText("reviewed", { exact: true })).toHaveCount(1);

  const frameworkFilter = page.getByRole("combobox", {
    name: "Filter crosswalk by framework",
  });
  await expect(
    frameworkFilter.locator("option", { hasText: "CIS AWS" }),
  ).toHaveCount(1);
  await expect(
    frameworkFilter.locator("option", { hasText: /^cis_aws$/ }),
  ).toHaveCount(0);

  const statusFilter = page.getByRole("combobox", {
    name: "Filter crosswalk by review status",
  });
  await statusFilter.selectOption("proposed");
  await expect(page.getByText(/^Showing 1–2 of 2 mappings$/)).toBeVisible();
  await expect(table.getByText("reviewed", { exact: true })).toHaveCount(0);
  await statusFilter.selectOption("reviewed");
  await expect(page.getByText(/^Showing 1–1 of 1 mappings$/)).toBeVisible();

  await expect(page.getByText(/heuristic$/)).toHaveCount(0);
});

test("crosswalk equivalence chips link to the control drawer", async ({
  page,
}) => {
  await page.goto("/console/crosswalk/");
  const chip = page.getByRole("link", { name: "SOC2-CC6.1" }).first();
  await expect(chip).toBeVisible({ timeout: 20_000 });
  await expect(chip).toHaveAttribute("href", /\/controls\/?\?id=SOC2-CC6\.1$/);
});

test.describe("dashboard honesty", () => {
  test.use({ timezoneId: "America/Los_Angeles" });

  test("low-coverage frameworks show coverage, not a score", async ({
    page,
  }) => {
    await page.route("**/api/v1/posture/current", async (route) => {
      const response = await route.fetch();
      const body = await response.json();
      body.data.evaluated_at = "2026-09-25T02:00:00Z";
      body.data.frameworks = [
        {
          framework: "ISO 27001",
          score: 95,
          state: "ready",
          control_count: 1,
          failing_control_count: 0,
          violation_count: 0,
          stale_control_count: 0,
          critical_violation_count: 0,
          high_violation_count: 0,
        },
      ];
      await route.fulfill({ response, json: body });
    });
    await page.route(
      (url) => url.pathname === "/api/v1/frameworks",
      async (route) => {
        const response = await route.fetch();
        const body = await response.json();
        body.data = body.data.map((row: { framework_id: string }) =>
          row.framework_id === "iso-27001-2022"
            ? { ...row, control_count: 93 }
            : row,
        );
        await route.fulfill({ response, json: body });
      },
    );

    await page.goto("/console/dashboard/");
    const list = page.getByRole("region", { name: "Framework posture list" });
    const iso = list.getByRole("link").filter({ hasText: "ISO 27001" });
    await expect(iso).toBeVisible({ timeout: 20_000 });
    await expect(iso).toContainText("1 of 93 controls assessed");
    await expect(iso).toContainText("Insufficient coverage");
    await expect(iso).not.toContainText("95");
    await expect(iso).not.toContainText("Ready");

    // Never show the UTC evaluation date; the header reads relative time.
    await expect(page.getByText("2026-09-25", { exact: true })).toHaveCount(0);
    await expect(page.getByText(/^Evaluated /)).toBeVisible();
    await expect(page.getByText("/ 100", { exact: true })).toBeVisible();
  });

  test("priority findings lead with the control title", async ({ page }) => {
    const controls = await (
      await page.request.get("/api/v1/controls?limit=1")
    ).json();
    const control = controls.data[0] as { control_id: string; title: string };
    await page.route("**/api/v1/posture/current", async (route) => {
      const response = await route.fetch();
      const body = await response.json();
      const seed = body.data.violations[0];
      body.data.violations = [
        {
          ...seed,
          violation_id: "v-honest-1",
          control_id: control.control_id,
          asset_id: "golden:asset:seed-1",
          severity: "critical",
          severity_score: 100,
        },
      ];
      await route.fulfill({ response, json: body });
    });

    await page.goto("/console/dashboard/");
    const findings = page.getByRole("region", { name: "Findings to triage" });
    const row = findings.getByRole("link").first();
    await expect(row).toBeVisible({ timeout: 20_000 });
    await expect(row).toContainText(control.title);
    await expect(row).toContainText(control.control_id);
    await expect(row).not.toContainText("golden:asset:seed-1");
  });
});

test("framework drawer reports mapped controls and pass/fail, not readiness", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/console/frameworks/");
  await page
    .getByRole("button", { name: /^Inspect / })
    .first()
    .click();
  const drawer = page.getByRole("dialog");
  await expect(drawer.getByText(/controls mapped/)).toBeVisible({
    timeout: 20_000,
  });
  await expect(
    drawer.getByText(/\d+ passing · \d+ failing · \d+ not evaluated/),
  ).toBeVisible();
  await expect(drawer.getByText(/controls implemented/)).toHaveCount(0);
  await expect(drawer.getByText(/threshold for claiming/)).toHaveCount(0);
  await expect(drawer.getByText(/sync_framework\.py/)).toHaveCount(0);
  await expect(drawer.getByText(/\b1 facts\b/)).toHaveCount(0);
  await expect(page.getByText(/pulled never/)).toHaveCount(0);
});
