import { expect, test } from "@playwright/test";

test("header reflects healthy and unavailable API responses", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/console/dashboard/");
  const header = page.getByRole("banner");
  await expect(
    header.getByText("API connected", { exact: true }),
  ).toBeVisible();
  await page.route("**/api/v1/healthz", (route) =>
    route.fulfill({
      status: 503,
      json: { error: "Synthetic unavailable API" },
    }),
  );
  await header.getByRole("button", { name: "Refresh data" }).click();
  await expect(
    header.getByText("API unavailable", { exact: true }),
  ).toBeVisible();
});

test("assessment overview links to workspaces and discloses provenance", async ({
  page,
}) => {
  await page.goto("/console/dashboard/");
  const overview = page.getByRole("region", {
    name: "Current assessment",
    exact: true,
  });
  await expect(
    overview.getByRole("link", { name: /Open findings/ }),
  ).toHaveAttribute("href", "/console/violations/");
  await expect(
    overview.getByRole("link", { name: /Control pass rate/ }),
  ).toHaveAttribute("href", "/console/controls/");
  await expect(
    overview.getByRole("link", { name: /Assessment export/ }),
  ).toHaveAttribute("href", "/console/audit-room/");
  await expect(
    overview.getByText("Assessment ID", { exact: true }),
  ).not.toBeVisible();
  await overview.getByText("Assessment details", { exact: true }).click();
  await expect(
    overview.getByText("Assessment ID", { exact: true }),
  ).toBeVisible();
  await overview.getByText("Assessment details", { exact: true }).click();
  await expect(
    overview.getByText("Assessment ID", { exact: true }),
  ).not.toBeVisible();
  // Escape and an outside click both dismiss it, like the popovers around it.
  await overview.getByText("Assessment details", { exact: true }).click();
  await page.keyboard.press("Escape");
  await expect(
    overview.getByText("Assessment ID", { exact: true }),
  ).not.toBeVisible();
  await overview.getByText("Assessment details", { exact: true }).click();
  await page.getByRole("heading", { level: 1, name: "Overview" }).click();
  await expect(
    overview.getByText("Assessment ID", { exact: true }),
  ).not.toBeVisible();
});

test("command palette is a combobox whose active option follows the keyboard", async ({
  page,
}) => {
  await page.goto("/console/dashboard/");
  await page.getByRole("button", { name: "Open command palette" }).click();
  const input = page.getByRole("combobox", { name: "Search the console" });
  await expect(input).toBeFocused();
  await input.fill("graph");
  const option = page.getByRole("option", { name: /Graph/ }).first();
  await expect(option).toHaveAttribute("aria-selected", "true");
  await expect(input).toHaveAttribute(
    "aria-activedescendant",
    (await option.getAttribute("id")) ?? "",
  );
  await input.press("Enter");
  await expect(page).toHaveURL(/\/console\/graph\/?/);
});

test("compact app header keeps search and account actions usable on mobile", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/console/dashboard/");
  const header = page.getByRole("banner");
  await header.getByRole("button", { name: "Open command palette" }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.keyboard.press("Escape");
  await header.getByRole("button", { name: /account menu/ }).click();
  await expect(page.getByRole("menu")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(
    header.getByRole("button", { name: "Capture snapshot" }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
});

test("overview leads with overall posture and distinguishes score from test pass rate", async ({
  page,
}) => {
  const postureResponse = await page.request.get("/api/v1/posture/current");
  const { data: assessment } = await postureResponse.json();
  const ingestionResponse = await page.request.get("/api/v1/ingestion/status");
  const { data: ingestion } = await ingestionResponse.json();
  await page.goto("/console/dashboard/");
  const overview = page.getByRole("region", {
    name: "Current assessment",
    exact: true,
  });
  await expect(
    overview.getByRole("progressbar", {
      name: "Assessment score",
      exact: true,
    }),
  ).toHaveAttribute(
    "aria-valuenow",
    String(Math.round(assessment.posture.score)),
  );
  await expect(
    overview.getByRole("progressbar", {
      name: "Control pass rate",
      exact: true,
    }),
  ).toHaveAttribute(
    "aria-valuenow",
    String(Math.round(ingestion.eval_accuracy.pass_rate * 100)),
  );
  await expect(
    overview.getByText(
      `${ingestion.eval_accuracy.passing} of ${ingestion.eval_accuracy.total_tests} tests passing`,
      { exact: true },
    ),
  ).toBeVisible();
  const accuracy = ingestion.eval_accuracy;
  // Unevaluated tests are named for what they need, not lumped into "Other".
  await expect(
    overview
      .getByRole("link", { name: /Control pass rate/ })
      .getByText(`${ingestion.eval_accuracy.needs_evidence} Needs evidence`, {
        exact: true,
      }),
  ).toBeVisible();
  expect(accuracy.needs_evidence).toBeGreaterThan(0);
});

test("unevaluated controls do not appear as a zero-percent result", async ({
  page,
}) => {
  await page.route("**/api/v1/ingestion/status", async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    body.data.eval_accuracy = {
      has_tests: false,
      total_tests: 0,
      passing: 0,
      failing: 0,
      warning: 0,
      pass_rate: 0,
    };
    await route.fulfill({ response, json: body });
  });
  await page.goto("/console/dashboard/");
  const passRate = page
    .getByRole("region", { name: "Current assessment", exact: true })
    .getByRole("link", { name: /Control pass rate/ });
  await expect(
    passRate.getByText("Not evaluated", { exact: true }),
  ).toBeVisible();
  await expect(passRate.getByRole("progressbar")).toHaveCount(0);
  await expect(passRate.getByText("0%", { exact: true })).toHaveCount(0);
});

test("overview shows actual finding severity and stays compact at tablet width", async ({
  page,
}) => {
  const response = await page.request.get("/api/v1/posture/current");
  const { data: assessment } = await response.json();
  const {
    open_violation_count: total,
    critical_violation_count: critical,
    high_violation_count: high,
  } = assessment.posture;
  await page.setViewportSize({ width: 720, height: 900 });
  await page.goto("/console/dashboard/");
  const overview = page.getByRole("region", {
    name: "Current assessment",
    exact: true,
  });
  await expect(
    overview.getByRole("img", {
      name: `Finding severity: ${critical} critical, ${high} high, ${Math.max(0, total - critical - high)} medium or low`,
      exact: true,
    }),
  ).toBeVisible();
  const bounds = await overview.boundingBox();
  expect(bounds).not.toBeNull();
  expect(bounds!.height).toBeLessThan(450);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
});
