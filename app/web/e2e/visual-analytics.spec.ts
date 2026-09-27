import { expect, test } from "@playwright/test";

const VIEWPORTS = [
  { name: "desktop-1440", width: 1440, height: 900 },
  { name: "desktop-1920", width: 1920, height: 1080 },
  { name: "mobile", width: 390, height: 844 },
] as const;

async function expectNoPageOverlap(page: import("@playwright/test").Page) {
  const dimensions = await page.evaluate(() => ({
    viewport: window.innerWidth,
    content: document.documentElement.scrollWidth,
  }));
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport + 1);
}

test.describe("visual analytics", () => {
  test("owner SLA heatmap drills into the remediation workbench", async ({
    page,
    request,
  }) => {
    const owner = `platform-${Date.now()}`;
    const created = await request.post("/api/v1/remediation/tasks", {
      data: {
        title: "Rotate repository deployment credential",
        owner,
        priority: "high",
        due_at: "2026-01-01T00:00:00Z",
      },
    });
    expect(created.ok()).toBeTruthy();

    await page.goto("/console/insights/");
    await expect(
      page.getByRole("heading", { name: "Remediation SLA heatmap" }),
    ).toBeVisible();
    const ownerRow = page.getByRole("row").filter({ hasText: owner });
    await expect(ownerRow).toBeVisible();
    await ownerRow.getByRole("link").click();

    await expect(page).toHaveURL(
      new RegExp(`/console/remediation/\\?owner=${owner}`),
    );
    await expect(page.getByText(`Filtered to ${owner}.`)).toBeVisible();
    await expect(
      page.getByText("Rotate repository deployment credential"),
    ).toBeVisible();
  });

  for (const viewport of VIEWPORTS) {
    test(`${viewport.name} analytics surfaces do not overflow`, async ({
      page,
    }, testInfo) => {
      await page.setViewportSize(viewport);
      for (const route of ["insights", "graph", "automation"] as const) {
        await page.goto(`/console/${route}/`);
        await expect(page.getByRole("main")).toBeVisible({ timeout: 20_000 });
        if (viewport.name === "mobile") {
          await expect(
            page.getByRole("button", { name: "Open navigation" }),
          ).toBeVisible();
        }
        if (route === "insights") {
          const heatmap = page.getByRole("heading", {
            name: "Remediation SLA heatmap",
          });
          await expect(heatmap).toBeVisible();
          await heatmap.scrollIntoViewIfNeeded();
        } else {
          const canvas = page.locator(".react-flow").first();
          await expect(canvas).toBeVisible();
          await canvas.scrollIntoViewIfNeeded();
        }
        await expectNoPageOverlap(page);
        await page.screenshot({
          path: testInfo.outputPath(`${viewport.name}-${route}.png`),
          fullPage: false,
        });
      }
    });
  }
});
