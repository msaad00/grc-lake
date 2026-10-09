import { expect, test } from "@playwright/test";

for (const [observed, evaluated, total] of [
  [8, 1, 10],
  [8, 5, 10],
  [8, 6, 10],
  [8, undefined, 10],
  [8, 5, undefined],
] as const) {
  test(`AI coverage distinguishes ${observed} observed from ${evaluated} evaluated of ${total}`, async ({
    page,
  }) => {
    const sufficient =
      evaluated !== undefined &&
      total !== undefined &&
      evaluated / total >= 0.5;
    const reason =
      "Insufficient framework coverage: current evaluated evidence must cover at least 50% of each observed AI framework's catalog.";
    await page.route("**/api/v1/stream", (route) =>
      route.fulfill({
        status: 200,
        contentType: "text/event-stream",
        body: "",
      }),
    );
    await page.route("**/api/v1/platform/ai-governance", (route) =>
      route.fulfill({
        json: {
          data: {
            state: "on_track",
            state_reason: reason,
            coverage_sufficient: sufficient,
            governance_score: 61,
            frameworks_ready: 0,
            frameworks_total: 1,
            inventory: {
              total: 1,
              models: 1,
              agents: 1,
              with_model_card: 1,
              with_lineage: 1,
            },
            events: {
              model_inventory: 1,
              model_lineage: 1,
              agent_runtime: 1,
              repo_artifacts: 1,
            },
            artifacts: { model_cards: 1 },
            evidence_loops: {},
            gaps: [],
            frameworks: [
              {
                framework_id: "nist-ai-rmf",
                label: "Test AI framework",
                requirements: total ?? 0,
                mapped_requirements: 8,
                mapped_pct: 80,
                controls_with_evidence: observed,
                evaluated_control_count: evaluated,
                catalog_control_count: total,
                coverage_sufficient: sufficient,
                passing_controls: 1,
                failing_controls: evaluated ? evaluated - 1 : 0,
                unevaluated_controls: observed - (evaluated ?? 0),
                score: 12.5,
              },
            ],
          },
        },
      }),
    );
    await page.route("**/api/v1/platform/ai-governance/inventory**", (route) =>
      route.fulfill({ json: { data: [] } }),
    );
    await page.goto("/console/ai-governance/");
    const strip = page.getByTestId("ai-governance-strip");
    await expect(
      strip.getByRole("button", {
        name: /About AI governance indicator: .*55% AI evidence signals.*45%/,
      }),
    ).toBeVisible();
    // One summary line, worded like the Overview framework rows.
    await expect(
      strip.getByText(
        `${observed} of ${total ?? "unknown"} controls assessed${
          evaluated && evaluated > 1 ? ` · ${evaluated - 1} failing` : ""
        } · 1 passing`,
        { exact: true },
      ),
    ).toBeVisible();
    if (!sufficient) {
      await expect(strip.getByText(reason, { exact: true })).toBeVisible();
      await expect(
        strip.getByText("Insufficient coverage", { exact: true }),
      ).toBeVisible();
      await expect(
        strip.getByText("12.5% passing", { exact: true }),
      ).toHaveCount(0);
    } else {
      await expect(
        strip.getByText("12.5% passing", { exact: true }),
      ).toBeVisible();
    }
    // Observed and currently evaluated stay distinct in the detail hint.
    await expect(
      strip.getByRole("button", {
        name: new RegExp(
          `About Test AI framework coverage: .*${evaluated ?? "unknown"}/${total ?? "unknown"} currently evaluated with fresh evidence`,
        ),
      }),
    ).toBeVisible();
  });
}
