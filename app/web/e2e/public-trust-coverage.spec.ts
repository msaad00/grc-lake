import { expect, test } from "@playwright/test";

for (const [evaluated, total, sufficient] of [
  [1, 93, false],
  [49, 100, false],
  [50, 100, true],
  [51, 100, true],
  [0, 100, false],
  [50, 0, false],
  [50, undefined, false],
] as const) {
  test(`public readiness at ${evaluated}/${total}`, async ({ page }) => {
    await page.route("**/api/public/trust/**", (route) =>
      route.fulfill({
        json: {
          schema_version: "trustops.public_trust.v1",
          posture: { state: "not_evaluated" },
          frameworks: [
            {
              framework: "ISO 27001:2022",
              state: "ready",
              score: 90,
              control_count: evaluated,
              evaluated_control_count: evaluated,
              catalog_control_count: total,
            },
          ],
        },
      }),
    );
    await page.goto("/console/trust/coverage-test");
    const score = page.getByTestId("framework-score");
    if (sufficient) {
      await expect(score).toContainText("90");
      await expect(score).toContainText("Ready");
    } else {
      await expect(score).toContainText("Insufficient coverage");
      await expect(score).not.toContainText("90");
      await expect(score).not.toContainText("Ready");
    }
    if (total)
      await expect(
        page.getByText(`${evaluated} / ${total} catalog controls evaluated`),
      ).toBeVisible();
  });
}
