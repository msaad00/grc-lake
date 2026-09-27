import {
  test,
  expect,
  type APIRequestContext,
  type Page,
} from "@playwright/test";

async function firstRecord(
  request: APIRequestContext,
  endpoint: string,
): Promise<Record<string, unknown>> {
  const response = await request.get(endpoint);
  expect(response.ok()).toBeTruthy();
  const records = (await response.json()).data ?? [];
  expect(records.length).toBeGreaterThan(0);
  return records[0];
}

async function expectPaletteDeepLink(
  page: Page,
  path: string,
  id: string,
  title = id,
) {
  await page.getByRole("button", { name: "Open command palette" }).click();
  const palette = page.getByRole("dialog", { name: "Search" });
  await expect(palette).toBeVisible();
  await palette.getByRole("combobox", { name: "Search the console" }).fill(id);
  // Indexes arrive independently. A related evidence subtitle may contain
  // the control ID before the actual control result has loaded.
  const result = palette.getByRole("option").filter({
    has: page.getByText(id, { exact: true }),
  });
  await expect(result).toHaveCount(1, { timeout: 15_000 });
  await expect(result).toBeVisible();
  await result.click();

  await expect(page).toHaveURL(
    new RegExp(`${path.replaceAll("/", "\\/")}\\?id=${encodeURIComponent(id)}`),
  );
  await expect(
    page.getByRole("dialog").getByRole("heading", { name: title }),
  ).toBeVisible({ timeout: 15_000 });
}

test.describe("record deep links", () => {
  test("open the requested control, finding, and evidence drawers", async ({
    page,
    request,
  }) => {
    const control = await firstRecord(request, "/api/v1/controls");
    const violation = await firstRecord(request, "/api/v1/violations");
    const evidence = await firstRecord(request, "/api/v1/evidence");

    await page.goto("/console/dashboard/");
    await expect(page.getByRole("main")).toBeVisible({ timeout: 20_000 });

    await expectPaletteDeepLink(
      page,
      "/console/controls/",
      String(control.control_id),
    );
    const controlDialog = page.getByRole("dialog");
    await page.waitForTimeout(500);
    const openPosition = await controlDialog.evaluate(
      (element) => element.getBoundingClientRect().x,
    );
    await controlDialog.getByRole("button", { name: "Close" }).click();
    await page.waitForTimeout(80);
    const exitPosition = await controlDialog.evaluate(
      (element) => element.getBoundingClientRect().x,
    );
    expect(exitPosition).toBeGreaterThan(openPosition);
    await expect(controlDialog).toHaveCount(0);

    const controls = (await (await request.get("/api/v1/controls")).json())
      .data as Array<Record<string, unknown>>;
    const violationControl = controls.find(
      (row) => row.control_id === violation.control_id,
    );
    await expectPaletteDeepLink(
      page,
      "/console/violations/",
      String(violation.violation_id),
      String(violationControl?.title ?? violation.event_type),
    );
    await page
      .getByRole("dialog")
      .getByText("Evidence & provenance", { exact: true })
      .click();
    await expect(
      page
        .getByRole("dialog")
        .getByText(String(violation.violation_id), { exact: true }),
    ).toBeVisible();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Close" })
      .click();
    await expect(page.getByRole("dialog")).toHaveCount(0);

    await expectPaletteDeepLink(
      page,
      "/console/evidence/",
      String(evidence.event_id),
    );
  });
});
