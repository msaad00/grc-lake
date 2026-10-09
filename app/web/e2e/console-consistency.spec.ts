import { expect, test, type Page } from "@playwright/test";

const PHONE = { width: 390, height: 844 };

async function noHorizontalOverflow(page: Page) {
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
}

test.describe("rail navigation", () => {
  test("the whole rail fits at 1440x900", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/console/agents/");
    const nav = page.getByRole("navigation", { name: "Primary" });
    await expect(nav.getByRole("link", { name: "Agents" })).toBeVisible();
    const fits = await nav.evaluate((el) => el.scrollHeight <= el.clientHeight);
    expect(fits).toBe(true);
    await expect(page.getByTestId("nav-fade-bottom")).toHaveCSS("opacity", "0");
  });

  test("a short window scrolls the active link into view and fades the hidden edge", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 640 });
    await page.goto("/console/audit-log/");
    const nav = page.getByRole("navigation", { name: "Primary" });
    const active = nav.locator('a[aria-current="page"]');
    await expect(active).toHaveText("Audit log");
    await expect(async () => {
      const [link, rail] = await Promise.all([
        active.boundingBox(),
        nav.boundingBox(),
      ]);
      expect(link!.y).toBeGreaterThanOrEqual(rail!.y);
      expect(link!.y + link!.height).toBeLessThanOrEqual(
        rail!.y + rail!.height + 1,
      );
    }).toPass({ timeout: 10_000 });
    // Links remain above the fold, so the top edge carries the hint.
    await expect(page.getByTestId("nav-fade-top")).toHaveCSS("opacity", "1");
  });
});

test.describe("tables become cards on phones", () => {
  test("findings cards keep severity and review visible at 390px", async ({
    page,
  }) => {
    await page.setViewportSize(PHONE);
    await page.goto("/console/violations/");
    const list = page.getByRole("list", { name: "Findings queue" });
    await expect(list).toBeVisible({ timeout: 20_000 });
    await expect(page.locator("table")).toHaveCount(0);
    const card = list.getByTestId("data-card").first();
    await expect(card).toBeVisible();
    // Severity chip, owner and asset labels are on the card, not off-screen.
    await expect(
      card.getByText(/^(Critical|High|Medium|Low|Info)$/),
    ).toBeVisible();
    await expect(card.getByText("Owner & source")).toBeVisible();
    const box = await card.boundingBox();
    expect(box!.x + box!.width).toBeLessThanOrEqual(PHONE.width);
    await card.click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await noHorizontalOverflow(page);
  });

  test("evidence cards show result and freshness, and filters fold away", async ({
    page,
  }) => {
    await page.setViewportSize(PHONE);
    await page.goto("/console/evidence/");
    const list = page.getByRole("list", { name: "Evidence records" });
    await expect(list).toBeVisible({ timeout: 20_000 });
    const card = list.getByTestId("data-card").first();
    await expect(
      card.getByText(/^(Passed|Failed|Blocked|Open|Warning|Error)$/).first(),
    ).toBeVisible();
    await expect(
      card.getByText(/^(Fresh|Stale|Expired|Missing|Not scored)$/).first(),
    ).toBeVisible();

    // The first record is on the first screen: filters start folded.
    const search = page.getByPlaceholder(/Search by source/);
    await expect(search).toBeHidden();
    expect((await card.boundingBox())!.y).toBeLessThan(PHONE.height);
    const toggle = page.getByRole("button", { name: /^Filters/ });
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await toggle.click();
    await expect(search).toBeVisible();
    await noHorizontalOverflow(page);
  });

  test("controls open with test cards above the fold", async ({ page }) => {
    await page.setViewportSize(PHONE);
    await page.goto("/console/controls/");
    const list = page.getByRole("list", {
      name: "Latest control test results",
    });
    await expect(list).toBeVisible({ timeout: 20_000 });
    await expect(
      page.getByRole("combobox", { name: "Filter by owner" }),
    ).toBeHidden();
    await page.getByRole("button", { name: /^Filters/ }).click();
    await expect(
      page.getByRole("combobox", { name: "Filter by owner" }),
    ).toBeVisible();
    await noHorizontalOverflow(page);
  });

  test("desktop keeps the sortable tables", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    for (const [route, name] of [
      ["violations", "Findings queue"],
      ["evidence", "Evidence records"],
    ] as const) {
      await page.goto(`/console/${route}/`);
      const region = page.getByRole("region", { name });
      await expect(region.locator("table")).toBeVisible({ timeout: 20_000 });
      await expect(page.getByRole("button", { name: /^Filters/ })).toBeHidden();
    }
  });
});

test.describe("graph opens readable", () => {
  test("the default view is one control path, fitted and labelled", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/console/graph/");
    const scope = page.getByTestId("graph-path-scope");
    await expect(scope).toContainText("Showing the path through");
    const nodes = page.locator(".react-flow__node");
    await expect(nodes.first()).toBeVisible();
    const count = await nodes.count();
    expect(count).toBeGreaterThan(2);
    expect(count).toBeLessThanOrEqual(25);
    await expect(page.getByText("Controls in view")).toBeVisible();
    await expect(page.getByText(/requirements in the catalog/)).toBeVisible();
    await expect(page.getByText("catalog totals")).toBeVisible();
  });

  test("on a phone the canvas starts on the first screen", async ({ page }) => {
    await page.setViewportSize(PHONE);
    await page.goto("/console/graph/");
    await expect(page.getByTestId("graph-summary-line")).toBeVisible();
    await expect(page.getByText("Controls in view")).toBeHidden();
    const canvas = page.locator(".react-flow").first();
    await expect(canvas).toBeVisible({ timeout: 20_000 });
    expect((await canvas.boundingBox())!.y).toBeLessThan(PHONE.height);
  });
});

test("workflow edges route between left and right handles without crossing nodes", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/console/automation/");
  const edges = page.locator(".react-flow__edge");
  await expect(edges.first()).toBeVisible({ timeout: 20_000 });
  expect(await page.locator(".react-flow__edge-smoothstep").count()).toBe(
    await edges.count(),
  );
  expect(
    await page
      .locator(".react-flow__handle-top, .react-flow__handle-bottom")
      .count(),
  ).toBe(0);
  const boxes = await page
    .locator(".react-flow__node")
    .evaluateAll((els) => els.map((el) => el.getBoundingClientRect().toJSON()));
  const labels = await page
    .locator(".react-flow__edge-textwrapper")
    .evaluateAll((els) => els.map((el) => el.getBoundingClientRect().toJSON()));
  const overlaps = (
    a: { x: number; y: number; width: number; height: number },
    b: { x: number; y: number; width: number; height: number },
  ) =>
    a.x < b.x + b.width &&
    b.x < a.x + a.width &&
    a.y < b.y + b.height &&
    b.y < a.y + a.height;
  for (const [i, a] of boxes.entries())
    for (const b of boxes.slice(i + 1)) expect(overlaps(a, b)).toBe(false);
  for (const label of labels)
    for (const node of boxes) expect(overlaps(label, node)).toBe(false);
});

test("chart tooltips use the themed surface in dark mode", async ({ page }) => {
  await page.request.post("/api/v1/insights/capture");
  await page.addInitScript(() =>
    window.localStorage.setItem("trustops:theme", JSON.stringify("dark")),
  );
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/console/insights/");
  const chart = page.locator(".recharts-wrapper").first();
  await expect(chart).toBeVisible({ timeout: 20_000 });
  const box = (await chart.boundingBox())!;
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  const tooltip = page.locator(".recharts-default-tooltip").first();
  await expect(tooltip).toBeVisible();
  const [background, surface] = await tooltip.evaluate((el) => {
    const probe = document.createElement("div");
    probe.style.background = "var(--color-surface)";
    document.body.appendChild(probe);
    const resolved = getComputedStyle(probe).backgroundColor;
    probe.remove();
    return [getComputedStyle(el).backgroundColor, resolved];
  });
  expect(background).toBe(surface);
  expect(background).not.toBe("rgb(255, 255, 255)");
});

test("empty lists share one empty state", async ({ page }) => {
  await page.route("**/api/v1/risks", (route) =>
    route.request().method() === "GET"
      ? route.fulfill({ json: { data: [] } })
      : route.fallback(),
  );
  await page.goto("/console/risks/");
  const empty = page.getByText("No risks recorded yet.", { exact: false });
  await expect(empty).toBeVisible({ timeout: 20_000 });
  await expect(
    page.locator("div.border-dashed").filter({ has: empty }).locator("svg"),
  ).toHaveCount(1);
});

test("risk form fields carry proper labels", async ({ page }) => {
  await page.goto("/console/risks/");
  for (const name of ["Title", "Category", "Owner"])
    await expect(page.getByRole("textbox", { name })).toBeVisible();
  for (const name of ["Severity", "Likelihood", "Impact"])
    await expect(page.getByRole("combobox", { name })).toBeVisible();
  await expect(page.getByText("load-bearing")).toHaveCount(0);
});
