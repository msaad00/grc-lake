import { expect, test, type Page } from "@playwright/test";

const PHONE = { width: 390, height: 844 };

async function tabStopsInRow(page: Page, rowIndex: number) {
  return page
    .locator("tbody tr")
    .nth(rowIndex)
    .evaluate((row) => {
      const focusable = row.querySelectorAll(
        "a[href], button:not([disabled]), input, select, textarea, [tabindex]:not([tabindex='-1'])",
      );
      return {
        rowTabIndex: row.getAttribute("tabindex"),
        rowRole: row.getAttribute("role"),
        count: focusable.length,
      };
    });
}

test.describe("data table rows have one real control", () => {
  test("findings rows: the Review button is the only tab stop", async ({
    page,
  }) => {
    await page.goto("/console/violations/");
    await expect(page.locator("tbody tr").first()).toBeVisible({
      timeout: 20_000,
    });
    const stops = await tabStopsInRow(page, 0);
    expect(stops).toEqual({ rowTabIndex: null, rowRole: null, count: 1 });
    await page
      .locator("tbody tr")
      .first()
      .getByRole("button", { name: /Review finding/ })
      .press("Enter");
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page).toHaveURL(/[?&]id=/);
  });

  test("evidence rows open from a named button, and the URL tracks it", async ({
    page,
  }) => {
    await page.goto("/console/evidence/");
    const open = page.getByRole("button", { name: /^Open evidence / }).first();
    await expect(open).toBeVisible({ timeout: 20_000 });
    expect(await tabStopsInRow(page, 0)).toEqual({
      rowTabIndex: null,
      rowRole: null,
      count: 1,
    });
    await open.focus();
    await page.keyboard.press("Enter");
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await expect(page).toHaveURL(/[?&]id=/);
    // The drawer shows the row's freshness, not a blank.
    await expect(
      dialog
        .getByTestId("evidence-drawer-freshness")
        .getByText(/^(Fresh|Stale|Expired|Missing|Not scored)$/),
    ).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await expect(page).not.toHaveURL(/[?&]id=/);
  });

  test("sort headers have one control each", async ({ page }) => {
    await page.goto("/console/evidence/");
    const header = page.locator("thead th").nth(1);
    await expect(header).toBeVisible({ timeout: 20_000 });
    expect(await header.getAttribute("onclick")).toBeNull();
    await header.getByRole("button").click();
    await expect(header).toHaveAttribute("aria-sort", /ascending|descending/);
  });

  test("phone cards keep list semantics", async ({ page }) => {
    await page.setViewportSize(PHONE);
    await page.goto("/console/violations/");
    const list = page.getByRole("list", { name: "Findings queue" });
    await expect(list).toBeVisible({ timeout: 20_000 });
    const card = list.getByRole("listitem").first();
    await expect(card).not.toHaveAttribute("role", "button");
    await expect(card.getByRole("term").first()).toBeVisible();
    await card.getByRole("button", { name: /^Open finding / }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
  });
});

test.describe("evidence page state", () => {
  test("a freshness failure keeps the records and says what is missing", async ({
    page,
  }) => {
    await page.route(/\/api\/v1\/evidence\/freshness(\?.*)?$/, (route) =>
      route.fulfill({ status: 500, json: { detail: "boom" } }),
    );
    await page.goto("/console/evidence/");
    await expect(
      page.getByRole("button", { name: /^Open evidence / }).first(),
    ).toBeVisible({ timeout: 20_000 });
    await expect(
      page.getByRole("alert").filter({ hasText: /evidence freshness/ }),
    ).toBeVisible();
    await expect(page.getByText("Freshness unavailable")).toBeVisible();
  });

  test("a ?control= filter counts as an active filter", async ({ page }) => {
    await page.setViewportSize(PHONE);
    await page.goto("/console/evidence/?control=SOC2-CC6.1");
    await expect(page.getByText("Control: SOC2-CC6.1")).toBeVisible({
      timeout: 20_000,
    });
    await expect(
      page.getByRole("button", { name: /^Filters/ }),
    ).toContainText("1 active");
  });
});

test.describe("findings saved views", () => {
  test("applying a view replaces the owner filter instead of keeping it", async ({
    page,
  }) => {
    await page.route("**/api/v1/saved-views**", (route) =>
      route.fulfill({
        json: {
          data: [
            {
              id: "legacy",
              name: "Critical only",
              surface: "violations",
              filters: { severity: "critical" },
            },
          ],
          meta: { count: 1 },
        },
      }),
    );
    await page.goto("/console/violations/?owner=__unassigned__");
    const owner = page.getByRole("combobox", { name: "Filter by owner" });
    await expect(owner).toHaveValue("__unassigned__", { timeout: 20_000 });
    await page.getByRole("button", { name: "Critical only" }).click();
    await expect(owner).toHaveValue("all");
    await expect(page).not.toHaveURL(/owner=/);
  });

  test("controls failure is stated, not silently replaced by IDs", async ({
    page,
  }) => {
    await page.route(/\/api\/v1\/controls(\?.*)?$/, (route) =>
      route.fulfill({ status: 500, json: { detail: "boom" } }),
    );
    await page.goto("/console/violations/");
    await expect(
      page.getByRole("alert").filter({ hasText: /control titles/ }),
    ).toBeVisible({ timeout: 20_000 });
    await expect(page.locator("tbody tr").first()).toBeVisible();
  });
});

test.describe("graph controls", () => {
  test("mode toggle reports its state and loads only the active graph", async ({
    page,
  }) => {
    const repoRequests: string[] = [];
    page.on("request", (request) => {
      if (/\/api\/v1\/repo-graph/.test(request.url()))
        repoRequests.push(request.url());
    });
    await page.goto("/console/graph/");
    const group = page.getByRole("group", { name: "Graph mode" });
    const compliance = group.getByRole("button", { name: "Compliance" });
    const repository = group.getByRole("button", { name: "Repository" });
    await expect(compliance).toHaveAttribute("aria-pressed", "true");
    await expect(repository).toHaveAttribute("aria-pressed", "false");
    const framework = page.getByRole("combobox", {
      name: "Filter graph by framework",
    });
    await expect(framework).not.toHaveValue("", { timeout: 45_000 });
    const defaultFramework = await framework.inputValue();
    expect(repoRequests).toEqual([]);

    await repository.click();
    await expect(repository).toHaveAttribute("aria-pressed", "true");
    await expect.poll(() => repoRequests.length).toBeGreaterThan(0);
    await compliance.click();
    // Back in compliance mode the default framework slice returns.
    await expect(framework).toHaveValue(defaultFramework, { timeout: 45_000 });
  });

  test("node search follows the ARIA combobox pattern", async ({ page }) => {
    await page.goto("/console/graph/");
    const search = page.getByRole("combobox", { name: "Search graph nodes" });
    await expect(search).toBeVisible({ timeout: 45_000 });
    await expect(search).toHaveAttribute("aria-expanded", "false");
    await search.fill("c");
    await expect(search).toHaveAttribute("aria-expanded", "true");
    const listbox = page.getByRole("listbox", { name: "Matching nodes" });
    await expect(search).toHaveAttribute(
      "aria-controls",
      (await listbox.getAttribute("id")) ?? "",
    );
    const options = listbox.getByRole("option");
    expect(await options.count()).toBeGreaterThan(1);
    await expect(options.nth(0)).toHaveAttribute("aria-selected", "true");
    await search.press("ArrowDown");
    await expect(options.nth(1)).toHaveAttribute("aria-selected", "true");
    await expect(options.nth(0)).toHaveAttribute("aria-selected", "false");
    await expect(search).toHaveAttribute(
      "aria-activedescendant",
      (await options.nth(1).getAttribute("id")) ?? "",
    );
    // Focus stays in the input; options are not separate tab stops.
    await expect(search).toBeFocused();
    expect(await options.nth(0).getAttribute("tabindex")).toBeNull();
    await search.press("Escape");
    await expect(search).toHaveAttribute("aria-expanded", "false");
  });

  test("a failed graph says unavailable instead of loading forever", async ({
    page,
  }) => {
    await page.route(/\/api\/v1\/graph(\?.*)?$/, (route) =>
      route.fulfill({ status: 500, json: { detail: "boom" } }),
    );
    await page.goto("/console/graph/");
    await expect(page.getByRole("alert")).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText("unavailable", { exact: true })).toBeVisible();
    // The mode toggle stays reachable so the other graph can still be opened.
    await expect(
      page
        .getByRole("group", { name: "Graph mode" })
        .getByRole("button", { name: "Repository" }),
    ).toBeVisible();
  });
});

test("loading copy uses the product name, not the architecture term", async ({
  page,
}) => {
  await page.route("**/api/v1/posture/current", async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 1_500));
    await route.continue();
  });
  await page.goto("/console/dashboard/");
  const status = page.getByRole("status").filter({ hasText: /Loading/ });
  await expect(status.first()).toContainText("GRC Lake evidence");
  await expect(page.getByText(/security data lake/i)).toHaveCount(0);
});
