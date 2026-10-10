import { test, expect } from "@playwright/test";

test.describe("dashboard product polish", () => {
  test("presents a coherent trust command center", async ({ page }) => {
    await page.goto("/console/dashboard/");

    const commandCenter = page.getByRole("region", {
      name: "Latest lake assessment",
    });
    await expect(commandCenter).toBeVisible({ timeout: 20_000 });
    await expect(
      commandCenter.getByRole("heading", { level: 2 }).first(),
    ).toBeVisible();
    for (const metric of [
      "Assessed coverage",
      "Open findings",
      "Assessment export",
    ]) {
      await expect(
        commandCenter.getByText(metric, { exact: true }),
      ).toBeVisible();
    }
    const frameworks = page.getByRole("region", {
      name: "Framework posture list",
    });
    await expect(
      frameworks.getByRole("img", { name: /framework$/ }).first(),
    ).toBeVisible();
    await expect(
      page.getByRole("tablist", { name: "Framework coverage views" }),
    ).toBeVisible();
    await expect(
      page.getByRole("tablist", { name: "Priority actions views" }),
    ).toBeVisible();
  });

  test("keeps workspace and theme controls available on desktop", async ({
    page,
  }) => {
    await page.goto("/console/dashboard/");
    await expect(
      page.getByRole("button", { name: /account menu/i }),
    ).toBeVisible({ timeout: 20_000 });
  });

  test("keeps the command center usable in mobile dark mode", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.addInitScript(() => {
      window.localStorage.setItem("trustops:theme", JSON.stringify("dark"));
    });
    await page.goto("/console/dashboard/");

    await expect(page.locator("html")).toHaveClass(/dark/);
    await expect(
      page.getByRole("region", { name: "Latest lake assessment" }),
    ).toBeVisible({ timeout: 20_000 });
    await expect(
      page
        .getByRole("region", { name: "Latest lake assessment" })
        .getByText("Needs attention", { exact: true }),
    ).toBeVisible();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
  });
});
