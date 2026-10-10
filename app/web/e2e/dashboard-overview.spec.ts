import { expect, test } from "@playwright/test";
import { workspaceCoverage } from "../src/lib/readiness-coverage";

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
    name: "Latest lake assessment",
    exact: true,
  });
  await expect(
    overview.getByRole("link", { name: /Open findings/ }),
  ).toHaveAttribute("href", "/console/violations/");
  await expect(
    overview.getByRole("link", { name: /Assessed coverage/ }),
  ).toHaveAttribute("href", "/console/controls/");
  await expect(
    overview.getByRole("link", { name: /Assessment export/ }),
  ).toHaveAttribute("href", "/console/audit-room/");
  // "Evaluated …" is the one disclosure for the assessment provenance.
  const details = overview.locator("summary", { hasText: /^Evaluated / });
  await expect(details).toContainText("assessment details");
  await expect(
    overview.getByText("Assessment ID", { exact: true }),
  ).not.toBeVisible();
  await details.click();
  await expect(
    overview.getByText("Assessment ID", { exact: true }),
  ).toBeVisible();
  await details.click();
  await expect(
    overview.getByText("Assessment ID", { exact: true }),
  ).not.toBeVisible();
  // Escape and an outside click both dismiss it, like the popovers around it.
  await details.click();
  await page.keyboard.press("Escape");
  await expect(
    overview.getByText("Assessment ID", { exact: true }),
  ).not.toBeVisible();
  await details.click();
  await page.getByRole("heading", { level: 1, name: "Overview" }).click();
  await expect(
    overview.getByText("Assessment ID", { exact: true }),
  ).not.toBeVisible();
});

test("every overview KPI is a label, one number, one line, no icon", async ({
  page,
}) => {
  await page.goto("/console/dashboard/");
  const overview = page.getByRole("region", {
    name: "Latest lake assessment",
    exact: true,
  });
  const tiles = overview.getByRole("link").filter({
    hasText:
      /^(Assessment score|Assessed coverage|Open findings|Evidence to refresh)/,
  });
  await expect(tiles).toHaveCount(4);
  for (const tile of await tiles.all()) {
    await expect(tile.locator("svg")).toHaveCount(0);
  }
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

test("overview leads with overall posture and distinguishes score from coverage", async ({
  page,
}) => {
  const postureResponse = await page.request.get("/api/v1/posture/current");
  const { data: assessment } = await postureResponse.json();
  const ingestionResponse = await page.request.get("/api/v1/ingestion/status");
  const { data: ingestion } = await ingestionResponse.json();
  const catalogResponse = await page.request.get(
    "/api/v1/frameworks?limit=500",
  );
  const { data: catalog } = await catalogResponse.json();
  const coverage = workspaceCoverage(assessment.frameworks, catalog);
  await page.goto("/console/dashboard/");
  const overview = page.getByRole("region", {
    name: "Latest lake assessment",
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
  expect(coverage.percent).not.toBeNull();
  await expect(
    overview.getByRole("progressbar", {
      name: "Assessed coverage",
      exact: true,
    }),
  ).toHaveAttribute("aria-valuenow", String(coverage.percent));
  // The two headline tiles answer different questions, so on the golden
  // fixture they must not print the same number.
  expect(coverage.percent).not.toBe(Math.round(assessment.posture.score));
  const accuracy = ingestion.eval_accuracy;
  await expect(
    overview
      .getByRole("link", { name: /Assessed coverage/ })
      .getByText(
        `${coverage.assessed.toLocaleString()} of ${coverage.total.toLocaleString()} requirements assessed · ${accuracy.needs_evidence} need evidence`,
        { exact: true },
      ),
  ).toBeVisible();
  await expect(
    overview.getByText("Control pass rate", { exact: true }),
  ).toHaveCount(0);
});

test("assessed coverage is not shown as zero before anything is evaluated", async ({
  page,
}) => {
  await page.route("**/api/v1/posture/current", async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    body.data.posture.state = "not_evaluated";
    await route.fulfill({ response, json: body });
  });
  // The live stream would replace the mocked posture with the real one.
  await page.route("**/api/v1/stream**", (route) => route.abort());
  await page.goto("/console/dashboard/");
  const tile = page
    .getByRole("region", { name: "Latest lake assessment", exact: true })
    .getByRole("link", { name: /Assessed coverage/ });
  await expect(tile.getByText("Not evaluated", { exact: true })).toBeVisible();
  await expect(tile.getByRole("progressbar")).toHaveCount(0);
  await expect(tile.getByText("0%", { exact: true })).toHaveCount(0);
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
    name: "Latest lake assessment",
    exact: true,
  });
  await expect(
    overview
      .getByRole("link", { name: /Open findings/ })
      .getByText(`${critical} critical · ${high} high`, { exact: true }),
  ).toBeVisible();
  await expect(
    overview
      .getByRole("link", { name: /Open findings/ })
      .getByText(String(total), { exact: true }),
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
