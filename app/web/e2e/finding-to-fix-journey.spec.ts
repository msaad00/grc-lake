import {
  expect,
  test,
  type APIRequestContext,
  type Page,
} from "@playwright/test";

const CONTROL_ID = "SOC2-CC6.4";
const CONTROL_TITLE = "Physical access is limited to authorized personnel";

async function findingFor(request: APIRequestContext, controlId: string) {
  const rows = (await (await request.get("/api/v1/violations")).json()).data;
  const match = rows.find(
    (row: { control_id: string }) => row.control_id === controlId,
  );
  expect(match, `golden fixture has a finding for ${controlId}`).toBeTruthy();
  return match as Record<string, string | number>;
}

// Findings show the asset's name; the golden fixture names every asset.
function assetShownFor(finding: Record<string, string | number>): string {
  expect(finding.asset_name, "golden assets carry a display name").toBeTruthy();
  return String(finding.asset_name);
}

async function expectNoHorizontalOverflow(page: Page) {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
}

test("finding drawer says what is wrong and how to fix it", async ({
  page,
  request,
}) => {
  const finding = await findingFor(request, CONTROL_ID);
  await page.goto("/console/violations/");
  const row = page.getByRole("row").filter({ hasText: CONTROL_TITLE }).first();
  await row.getByText(assetShownFor(finding), { exact: true }).click();

  const drawer = page.getByRole("dialog");
  await expect(
    drawer.getByRole("heading", { name: CONTROL_TITLE }),
  ).toBeVisible();
  await expect(drawer).toContainText(CONTROL_ID);
  await expect(drawer.getByText("Suggested remediation")).toBeVisible();
  await expect(drawer.getByText("Business impact")).toHaveCount(0);
  await expect(
    drawer.getByRole("combobox", { name: "State", exact: true }),
  ).toHaveValue(String(finding.state));
  await expect(
    drawer.getByRole("link", { name: /Trace in graph/ }),
  ).toHaveAttribute(
    "href",
    `/console/graph/?focus=${encodeURIComponent(`control:${CONTROL_ID}`)}`,
  );
  await drawer.getByRole("button", { name: "Close", exact: true }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);

  await row.focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("dialog").getByRole("heading", { name: CONTROL_TITLE }),
  ).toBeVisible();
});

test("finding task stays open without an independent human SSO reviewer", async ({
  page,
  request,
}) => {
  const finding = await findingFor(request, CONTROL_ID);
  await page.goto(
    `/console/violations/?id=${encodeURIComponent(String(finding.violation_id))}`,
  );
  await page
    .getByRole("dialog")
    .getByRole("link", { name: /Create task/ })
    .click();

  await expect(page).toHaveURL(/\/console\/remediation\/\?/);
  // Let the target page's queries settle before asserting on prefilled values.
  await page.waitForLoadState("networkidle");
  const url = new URL(page.url());
  expect(url.searchParams.get("control")).toBe(CONTROL_ID);
  expect(url.searchParams.get("finding")).toBe(String(finding.violation_id));
  await expect(
    page.getByRole("textbox", { name: "Task title", exact: true }),
  ).toHaveValue(CONTROL_TITLE);
  await expect(
    page.getByRole("textbox", { name: "Control ID", exact: true }),
  ).toHaveValue(CONTROL_ID);
  await expect(
    page.getByRole("textbox", { name: "Owner", exact: true }),
  ).toHaveValue(String(finding.asset_owner));
  await expect(
    page.getByRole("combobox", { name: "Task priority" }),
  ).toHaveValue(
    { critical: "critical", high: "high", medium: "medium" }[
      String(finding.severity)
    ] ?? "low",
  );
  await expect(page.getByText(`Showing tasks for ${CONTROL_ID}`)).toBeVisible();

  const title = `${CONTROL_TITLE} ${Date.now()}`;
  await page
    .getByRole("textbox", { name: "Task title", exact: true })
    .fill(title);
  const created = page.waitForResponse(
    (r) =>
      r.url().endsWith("/api/v1/remediation/tasks") &&
      r.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Add task", exact: true }).click();
  const body = (await (await created).json()).data;
  expect(body.violation_id).toBe(finding.violation_id);
  expect(body.control_id).toBe(CONTROL_ID);

  const taskRow = page.getByTestId(`task-${body.id}`);
  await expect(taskRow).toContainText(title);
  await expect(
    taskRow.getByRole("link", { name: /From finding/ }),
  ).toHaveAttribute(
    "href",
    `/console/violations/?id=${encodeURIComponent(String(finding.violation_id))}`,
  );

  await taskRow.getByRole("button", { name: "Resolve", exact: true }).click();
  const modal = page.getByRole("dialog", { name: "Resolve task" });
  await expect(modal).toBeVisible();
  const proof = "https://github.com/acme/infra/pull/42";
  await modal
    .getByRole("textbox", { name: /Evidence link or note/ })
    .fill(proof);
  const verified = page.waitForResponse(
    (r) =>
      r.url().endsWith(`/api/v1/remediation/tasks/${body.id}/verify`) &&
      r.request().method() === "POST",
  );
  await modal.getByRole("button", { name: "Verify and resolve" }).click();
  expect((await verified).status()).toBe(403);
  await expect(modal).toContainText("Unable to resolve task");
  await expect(
    modal.getByRole("textbox", { name: /Evidence link or note/ }),
  ).toHaveValue(proof);
  const current = (
    await (await request.get(`/api/v1/remediation/tasks/${body.id}`)).json()
  ).data;
  expect(current.status).toBe("open");
  expect(current.verification_history).toEqual([]);
});

test("owner filters sync to the URL on findings and tasks", async ({
  page,
  request,
}) => {
  const base = (await (await request.get("/api/v1/violations")).json()).data;
  const owners = ["alice-sec", "bob-cloud", ""];
  const rows = base.slice(0, 3).map((v: object, i: number) => ({
    ...v,
    violation_id: `owner-fixture-${i}`,
    asset_owner: owners[i],
  }));
  await page.route(/\/api\/v1\/violations(?:\?.*)?$/, (route) =>
    route.fulfill({
      json: { data: rows, pagination: { count: 3, has_more: false } },
    }),
  );
  await page.goto("/console/violations/");
  const ownerFilter = page.getByRole("combobox", { name: "Filter by owner" });
  await ownerFilter.selectOption("bob-cloud");
  await expect(page).toHaveURL(/[?&]owner=bob-cloud/);
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await expect(page.locator("tbody")).toContainText("bob-cloud");
  await page.reload();
  await expect(
    page.getByRole("combobox", { name: "Filter by owner" }),
  ).toHaveValue("bob-cloud");
  await expect(page.locator("tbody tr")).toHaveCount(1);

  const owner = `owner-filter-${Date.now()}`;
  await request.post("/api/v1/remediation/tasks", {
    data: { title: `Owned by ${owner}`, owner },
  });
  await page.goto("/console/remediation/");
  const taskOwner = page.getByRole("combobox", {
    name: "Filter tasks by owner",
  });
  await taskOwner.selectOption(owner);
  await expect(page).toHaveURL(new RegExp(`[?&]owner=${owner}`));
  await expect(page.getByText(`Filtered to ${owner}.`)).toBeVisible();
  await expect(page.getByText(`Owned by ${owner}`)).toBeVisible();
});

test("control drawer links evidence, labels findings, and traces in graph", async ({
  page,
  request,
}) => {
  const finding = await findingFor(request, CONTROL_ID);
  await page.goto(`/console/controls/?id=${CONTROL_ID}`);
  const drawer = page.getByRole("dialog");
  const evidence = drawer.getByRole("link", { name: /Evidence \d+\/\d+/ });
  await expect(evidence).toHaveAttribute(
    "href",
    `/console/evidence/?control=${encodeURIComponent(CONTROL_ID)}`,
  );
  const findingButton = drawer.getByRole("button", {
    name: new RegExp(assetShownFor(finding)),
  });
  await expect(findingButton).toBeVisible();
  await expect(findingButton).not.toContainText(String(finding.event_id));

  await evidence.click();
  await expect(page).toHaveURL(/\/console\/evidence\/\?control=/);
  await expect(page.getByText(`Control: ${CONTROL_ID}`)).toBeVisible();
  const evidenceRows = page.locator("tbody tr");
  await expect(evidenceRows.first()).toContainText(CONTROL_ID);
  for (const text of await evidenceRows.allInnerTexts())
    expect(text).toContain(CONTROL_ID);

  await page.goto(`/console/controls/?id=${CONTROL_ID}`);
  await page
    .getByRole("dialog")
    .getByRole("link", { name: /Trace in graph/ })
    .click();
  await expect(page).toHaveURL(/\/console\/graph\/\?focus=control/);
  await expect(page.locator(".react-flow__node.focused")).toHaveCount(1);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator(".react-flow__node.focused")).toContainText(
    CONTROL_ID,
  );
});

test("graph search picks the trace start node", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/console/graph/");
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
  await page.getByRole("button", { name: "Trace path" }).click();
  await page.getByLabel("Search graph nodes").fill(CONTROL_ID);
  await page
    .getByRole("listbox", { name: "Matching nodes" })
    .getByRole("option", { name: new RegExp(CONTROL_ID) })
    .click();
  await expect(
    page.getByRole("button", { name: "Pick end node" }),
  ).toBeVisible();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator(".react-flow__node.focused")).toContainText(
    CONTROL_ID,
  );
});

test("control queue rows open the drawer and obey the filters", async ({
  page,
}) => {
  await page.goto("/console/controls/");
  const queue = page.getByRole("region", {
    name: "Latest control test results",
  });
  await expect(queue).toBeVisible();
  await expect(page.getByTestId("control-card-grid")).toHaveCount(0);

  const result = page.getByRole("combobox", { name: "Filter by result" });
  await result.selectOption("pass");
  const rows = queue.locator("tbody tr");
  await expect(rows.first()).toBeVisible();
  for (const text of await rows.allInnerTexts()) expect(text).toContain("Pass");

  const owner = page.getByRole("combobox", { name: "Filter by owner" });
  await owner.selectOption("grc");
  for (const text of await rows.allInnerTexts()) expect(text).toContain("grc");

  await rows.first().click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Close", exact: true })
    .click();

  await page.getByRole("button", { name: "Card grid" }).click();
  await expect(page.getByTestId("control-card-grid")).toBeVisible();
});

for (const route of ["violations", "remediation", "controls"]) {
  test(`${route} has no horizontal overflow at 390px`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(`/console/${route}/`);
    await expect(page.getByRole("main")).toBeVisible();
    await page.waitForTimeout(1500);
    await expectNoHorizontalOverflow(page);
  });
}
