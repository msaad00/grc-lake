import { expect, test } from "@playwright/test";

for (const marker of [true, false, undefined]) {
  test(`public synthetic evidence notice with marker ${marker}`, async ({
    page,
  }) => {
    await page.route("**/api/public/trust/**", (route) =>
      route.fulfill({
        json: {
          schema_version: "trustops.public_trust.v1",
          synthetic_fixture: marker,
          posture: { state: "not_evaluated" },
          frameworks: [],
        },
      }),
    );
    await page.goto("/console/trust/provenance-test");
    await expect(page.getByTestId("trust-posture-card")).toBeVisible();
    const notice = page.getByRole("note").filter({
      hasText:
        "Contains synthetic demonstration evidence; synthetic rows are not production proof.",
    });
    if (marker === true) await expect(notice).toBeVisible();
    else await expect(notice).toHaveCount(0);
  });
}
