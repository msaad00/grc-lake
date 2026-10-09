import { expect, test, type Page } from "@playwright/test";

async function openQueue(page: Page) {
  await page.goto("/console/mapping-review/");
  await expect(
    page.getByRole("heading", { level: 1, name: "Mapping review" }),
  ).toBeVisible({ timeout: 20_000 });
  const table = page.getByRole("table", { name: "Mappings to review" });
  await expect(table.getByRole("row").nth(1)).toBeVisible({ timeout: 20_000 });
  return table;
}

test.describe("mapping review", () => {
  test("shows per-framework progress with the review states kept apart", async ({
    page,
  }) => {
    await openQueue(page);
    const progress = page.getByRole("region", { name: "Review progress" });
    await expect(progress).toBeVisible();
    for (const label of [
      "Maintainer-reviewed",
      "Org-reviewed",
      "Needs changes",
      "Rejected",
      "Pending",
    ]) {
      await expect(
        progress.locator("summary").getByText(label, { exact: true }),
      ).toBeVisible();
    }
    // The shared glossary defines each state on demand.
    await progress.getByText("What these mean").click();
    await expect(
      progress.getByText(
        "Approved by a reviewer in your organization, with a rationale.",
      ),
    ).toBeVisible();
    await expect(
      progress.getByText(/org-reviewed \d[\d,]* of \d[\d,]* mappings/).first(),
    ).toBeVisible();
    // The unit is mappings here; Frameworks counts requirements.
    await expect(
      progress.getByText(/^Of \d[\d,]* safeguard-to-requirement mappings:/),
    ).toBeVisible();
    await expect(
      progress.getByText(/Counts are mappings, not requirements/),
    ).toBeVisible();
    // An empty decision log never reads as "verified · 0".
    await expect(progress.getByText(/Decision log verified · 0/)).toHaveCount(
      0,
    );
  });

  test("insecure console cannot approve a pending mapping", async ({
    page,
  }) => {
    const table = await openQueue(page);
    const rationale = `Evidence confirms the requirement (e2e ${Date.now()})`;

    const firstRow = table.getByRole("row").nth(1);
    const requirement = (await firstRow.getAttribute("data-mapping")) ?? "";
    expect(requirement).toContain("|");
    const [safeguardId, controlId] = requirement.split("|");

    // Keyboard: the row checkbox is reachable and toggles with Space.
    const checkbox = firstRow.getByRole("checkbox");
    await checkbox.focus();
    await page.keyboard.press("Space");
    await expect(checkbox).toBeChecked();

    const decision = page.getByRole("region", { name: "Record a decision" });
    await expect(decision.getByText("1 selected")).toBeVisible();
    const approve = decision.getByRole("button", { name: "Approve" });
    await expect(approve).toBeDisabled();
    await decision.getByLabel("Rationale").fill(rationale);
    await approve.click();

    // This browser suite uses the explicitly unauthenticated demo server.
    // Successful authenticated review is covered by test_mapping_review_api.py.
    await expect(
      page.getByText(
        /mapping review decisions require a signed-in console session/,
      ),
    ).toBeVisible();
    await expect(page.getByText("Recorded 1 decision")).toHaveCount(0);
    await expect(
      table.locator(`tr[data-mapping="${safeguardId}|${controlId}"]`),
    ).toBeVisible();
  });

  test("works at 390px without horizontal page scroll", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await openQueue(page);
    const overflow = await page.evaluate(
      () =>
        document.documentElement.scrollWidth -
        document.documentElement.clientWidth,
    );
    expect(overflow).toBeLessThanOrEqual(1);
    await expect(
      page.getByRole("combobox", { name: "Filter by framework" }),
    ).toBeVisible();
  });

  test("frameworks page links to the review queue and splits reviewer types", async ({
    page,
  }) => {
    await page.goto("/console/frameworks/");
    const portfolio = page.getByRole("region", {
      name: "Framework coverage summary",
    });
    await expect(portfolio).toBeVisible({ timeout: 20_000 });
    await expect(portfolio.getByText(/maintainer-reviewed/)).toBeVisible();
    await expect(portfolio.getByText(/org-reviewed/)).toBeVisible();
    await portfolio.getByRole("link", { name: "Review mappings" }).click();
    await expect(
      page.getByRole("heading", { level: 1, name: "Mapping review" }),
    ).toBeVisible({ timeout: 20_000 });
  });
});

test("contextual mappings are visibly separate from coverage", async ({
  page,
}) => {
  await page.route("**/api/v1/mapping-reviews/queue?**", async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    if (Array.isArray(body.data) && body.data.length > 1) {
      body.data[0] = {
        ...body.data[0],
        role: "supporting",
        contributes_to_coverage: false,
      };
      body.data[1] = {
        ...body.data[1],
        role: "inherited",
        contributes_to_coverage: false,
      };
    }
    await route.fulfill({ response, json: body });
  });
  const table = await openQueue(page);
  await expect(
    table.getByText("Context only · no coverage credit"),
  ).toHaveCount(2);
  await expect(table.getByText("supporting", { exact: true })).toBeVisible();
  await expect(table.getByText("inherited", { exact: true })).toBeVisible();
});
