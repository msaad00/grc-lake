import { test, expect } from "@playwright/test";

test.describe("framework coverage workflow", () => {
  test("surfaces portfolio coverage and actionable filters", async ({
    page,
  }) => {
    await page.goto("/console/frameworks/");

    const portfolio = page.getByRole("region", {
      name: "Framework coverage summary",
    });
    await expect(portfolio).toBeVisible({ timeout: 20_000 });
    await expect(
      portfolio.getByRole("heading", { name: "Requirement coverage" }),
    ).toBeVisible();
    await expect(portfolio.getByText("Catalogued requirements")).toBeVisible();
    await expect(portfolio.getByText("Mapped requirements")).toBeVisible();
    await expect(
      portfolio.getByText("Reviewed requirements", { exact: true }),
    ).toBeVisible();
    await expect(
      portfolio.getByText(/requirements with a reviewed mapping/),
    ).toBeVisible();
    await expect(
      portfolio.getByText("Proposed mappings awaiting review"),
    ).toHaveCount(0);
    await expect(
      portfolio.getByText("Review backlog", { exact: true }),
    ).toBeVisible();

    await expect(
      page.getByRole("searchbox", { name: "Search frameworks" }),
    ).toBeVisible();
    await expect(
      page.getByRole("combobox", { name: "Filter by readiness" }),
    ).toHaveCount(0);
    await page.getByRole("button", { name: "Show filters" }).click();
    await expect(
      page.getByRole("combobox", { name: "Filter by readiness" }),
    ).toBeVisible();
    await expect(
      page.getByRole("combobox", { name: "Filter by source health" }),
    ).toBeVisible();

    await expect(
      page.getByRole("region", { name: "Readiness details" }),
    ).toHaveCount(0);
    await page.getByRole("button", { name: "Show readiness details" }).click();
    await expect(
      page.getByRole("region", { name: "Readiness details" }),
    ).toBeVisible();
  });

  test("filters framework cards without hiding source provenance", async ({
    page,
  }) => {
    await page.goto("/console/frameworks/");

    const search = page.getByRole("searchbox", { name: "Search frameworks" });
    await search.fill("NIST AI");

    const results = page.getByRole("region", { name: "Framework catalog" });
    await expect(
      results.getByText(/NIST AI Risk Management/i).first(),
    ).toBeVisible();
    await expect(
      results.getByText("official source", { exact: true }).first(),
    ).toBeVisible();
    await expect(results).toContainText("source-cited");
  });

  test("keeps the portfolio usable on mobile", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/console/frameworks/");

    await expect(
      page.getByRole("region", { name: "Framework coverage summary" }),
    ).toBeVisible({ timeout: 20_000 });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
  });
});

test("shows observed-asset safeguard results without implying complete coverage", async ({
  page,
}) => {
  await page.goto("/console/frameworks/");
  const summary = page.getByText("Safeguard assessment · observed assets", {
    exact: true,
  });
  await summary.click();
  const assessment = page.locator("details").filter({ has: summary });
  await expect(assessment).toContainText(
    "Complete asset inventory is not established.",
  );
  await expect(assessment.getByRole("table")).toBeVisible();
  // Golden evidence has framework tags but no explicit safeguard assertions.
  await expect(assessment).toContainText("0 passing");
  await expect(
    assessment.getByRole("row").filter({ hasText: "SG-IDENTITY-001" }),
  ).toContainText("not evaluated");
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
});
