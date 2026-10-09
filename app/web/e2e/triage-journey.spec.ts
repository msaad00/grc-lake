import { test, expect } from "@playwright/test";

test.use({
  timezoneId: "America/New_York",
  extraHTTPHeaders: process.env.GRC_LAKE_TEST_TOKEN
    ? { Authorization: `Bearer ${process.env.GRC_LAKE_TEST_TOKEN}` }
    : {},
});

test("dashboard opens the selected finding and closing clears the link", async ({
  page,
}) => {
  await page.goto("/console/dashboard/");
  const finding = page
    .getByRole("region", { name: "Findings to triage" })
    .getByRole("link")
    .first();
  await expect(finding).toHaveAttribute("href", /violations.*id=/);
  await finding.click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Close", exact: true })
    .click();
  await expect(page).not.toHaveURL(/[?&]id=/);
  await page.reload();
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("environment filtering preserves unknown context and severity", async ({
  page,
  request,
}) => {
  const response = await request.get("/api/v1/violations");
  const body = await response.json();
  const rows = body.data.slice(0, 3).map((v: object, i: number) => ({
    ...v,
    violation_id: `triage-fixture-${i}`,
    environment: ["prod", "staging", ""][i],
  }));
  await page.route(/\/api\/v1\/violations(?:\?.*)?$/, (route) =>
    route.fulfill({
      json: { data: rows, pagination: { count: 3, has_more: false } },
    }),
  );
  await page.goto("/console/violations/");
  const filter = page.getByRole("combobox", { name: "Filter by environment" });
  await expect(filter).toBeVisible();
  await filter.selectOption("prod");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await expect(page.locator("tbody")).toContainText("Critical");
  await filter.selectOption("unknown");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await expect(page.locator("tbody")).toContainText("Unknown");
  await page.getByRole("button", { name: /Review finding/ }).click();
  await expect(page.getByRole("dialog")).toContainText("Unknown");
  await expect(page.getByRole("dialog")).toContainText("Critical");
});

test("control evidence request opens a prefilled form and reports save failure", async ({
  page,
}) => {
  await page.goto("/console/controls/?id=SOC2-CC6.4");
  await expect(page.getByRole("dialog")).toBeVisible();
  await page
    .getByRole("dialog")
    .getByRole("link", { name: "Request evidence" })
    .click();
  await expect(
    page.getByRole("tab", { name: "Evidence requests", exact: true }),
  ).toHaveAttribute("aria-selected", "true");
  // Let the target page's queries settle before asserting on prefilled values.
  await page.waitForLoadState("networkidle");
  await expect(
    page.getByRole("textbox", { name: "Control ID", exact: true }),
  ).toHaveValue("SOC2-CC6.4");
  await page.route(
    /\/api\/v1\/remediation\/evidence-requests$/,
    async (route) => {
      if (route.request().method() === "POST") {
        expect(route.request().postDataJSON().control_id).toBe("SOC2-CC6.4");
        await route.fulfill({
          status: 503,
          json: { detail: "Service unavailable" },
        });
      } else await route.continue();
    },
  );
  await page
    .getByRole("button", { name: "Request evidence", exact: true })
    .click();
  await expect(page.getByRole("main").getByRole("alert")).toContainText(
    "Unable to save",
  );
  await expect(
    page.getByRole("textbox", { name: "Control ID", exact: true }),
  ).toHaveValue("SOC2-CC6.4");
});

test("authenticated evidence request persists in the local store", async ({
  page,
  request,
}) => {
  test.skip(
    !process.env.GRC_LAKE_TEST_TOKEN,
    "Requires an ephemeral authenticated test session",
  );
  await page.goto("/console/remediation/?tab=evidence&control=SOC2-CC6.4");
  await page
    .getByRole("textbox", { name: "Requested from", exact: true })
    .fill("local-ui-reviewer");
  const saved = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/v1/remediation/evidence-requests") &&
      response.request().method() === "POST",
  );
  await page
    .getByRole("button", { name: "Request evidence", exact: true })
    .click();
  const response = await saved;
  expect(response.ok()).toBeTruthy();
  const created = (await response.json()).data;
  try {
    await expect(page.getByRole("main").getByRole("status")).toContainText(
      "Evidence request saved.",
    );
    const stored = await (
      await request.get("/api/v1/remediation/evidence-requests")
    ).json();
    expect(stored.data).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: created.id,
          control_id: "SOC2-CC6.4",
          requested_from: "local-ui-reviewer",
        }),
      ]),
    );
  } finally {
    await request.patch(`/api/v1/remediation/evidence-requests/${created.id}`, {
      data: { status: "cancelled" },
    });
  }
});

test("failed triage keeps edits visible without a success notification", async ({
  page,
  request,
}) => {
  const rows = (await (await request.get("/api/v1/violations")).json()).data;
  let submittedDue: string | undefined;
  await page.route(/\/api\/v1\/violations\/[^/]+\/triage$/, (route) => {
    submittedDue = route.request().postDataJSON().due_at;
    return route.fulfill({
      status: 503,
      json: { detail: "Service unavailable" },
    });
  });
  await page.goto(
    `/console/violations/?id=${encodeURIComponent(rows[0].violation_id)}`,
  );
  const drawer = page.getByRole("dialog");
  await drawer
    .getByRole("textbox", { name: "Assignee", exact: true })
    .fill("local-ui-reviewer");
  await expect(drawer.getByLabel("Due date", { exact: true })).toBeVisible();
  await drawer.getByLabel("Due date", { exact: true }).fill("2026-10-01T17:00");
  await drawer
    .getByRole("button", { name: "Save triage", exact: true })
    .click();
  await expect(drawer.getByRole("alert")).toContainText(
    "Unable to save triage",
  );
  await expect(
    drawer.getByRole("textbox", { name: "Assignee", exact: true }),
  ).toHaveValue("local-ui-reviewer");
  expect(submittedDue).toBe("2026-10-01T21:00:00.000Z");
  await expect(drawer.getByLabel("Due date", { exact: true })).toHaveValue(
    "2026-10-01T17:00",
  );
  await expect(page.getByText(/Triage recorded:/)).toHaveCount(0);
});
