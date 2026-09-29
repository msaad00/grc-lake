import { expect, test } from "@playwright/test";

test("insights explains capture and empty MTTR/SLA in plain language", async ({
  page,
}) => {
  await page.route("**/api/v1/insights/remediation", (route) =>
    route.fulfill({
      json: {
        data: {
          open: 3,
          overdue: 0,
          mttr_hours: null,
          sla_attainment_pct: null,
          resolved_count: 0,
          sla_eligible_count: 0,
        },
      },
    }),
  );
  await page.goto("/console/insights/");
  await expect(page.getByText(/POST \/api/)).toHaveCount(0);
  await expect(page.getByText(/wire the scheduler/)).toHaveCount(0);
  await expect(
    page.getByText("Appears after the first task is resolved.").first(),
  ).toBeVisible();
});

test("evidence page describes the data flow without layer jargon", async ({
  page,
}) => {
  await page.goto("/console/evidence/");
  await expect(page.getByText(/Bronze raw/)).toHaveCount(0);
  await expect(page.getByText(/silver facts/i)).toHaveCount(0);
});

test("audit log uses labels, local times, and puts the event before the hash", async ({
  page,
}) => {
  await page.route("**/api/v1/audit-log**", (route) =>
    route.fulfill({
      json: {
        data: [
          {
            event_id: "evt_0123456789abcdef",
            category: "trust_share",
            actor: "admin@example.test",
            occurred_at: "2026-09-24T12:34:56.123456Z",
            summary: "Issued trust share",
            subject: "shr_abc",
            result: null,
            payload: {},
          },
        ],
        meta: { count: 1 },
      },
    }),
  );
  await page.goto("/console/audit-log/");
  await expect(page.getByText(/in gold\//)).toHaveCount(0);
  await expect(page.getByText(/trust_share/)).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: /Trust shares/ }).first(),
  ).toBeVisible();
  await expect(page.getByText(/\.123456/)).toHaveCount(0);

  const row = page.getByRole("button", { name: /Issued trust share/ });
  const text = (await row.textContent()) ?? "";
  expect(text.indexOf("Issued trust share")).toBeLessThan(
    text.indexOf("evt_0123456789abcdef"),
  );
});

test("audit room freshness panel speaks in hours and pluralises", async ({
  page,
}) => {
  // The live stream would overwrite the mocked summary with real lake data.
  await page.route("**/api/v1/stream**", (route) => route.abort());
  await page.route("**/api/v1/evidence/freshness/summary**", (route) =>
    route.fulfill({
      json: {
        data: {
          total: 1,
          fresh_count: 0,
          stale_count: 1,
          expired_count: 0,
          missing_count: 0,
          sla_breach_count: 1,
          fresh_rate_pct: 0,
          state: "action_required",
          sources_needing_action: 1,
          top_breaches: [],
          sources: [
            {
              source: "okta",
              connector_id: "okta",
              fresh_count: 0,
              stale_count: 1,
              expired_count: 0,
              missing_count: 0,
              evidence_count: 1,
              latest_evidence_at: null,
              freshness_slo_minutes: 1440,
              state: "action_required",
              status: "stale",
              next_action: "sync",
            },
          ],
        },
      },
    }),
  );
  await page.goto("/console/audit-room/");
  await page.getByRole("tab", { name: "Freshness" }).click();
  const panel = page.getByTestId("freshness-sla-panel");
  await expect(panel.getByText(/1 record · refresh every 24h/)).toBeVisible();
  await expect(panel.getByText("1 breach", { exact: true })).toBeVisible();
  await expect(panel.getByText(/1440m/)).toHaveCount(0);
  await expect(panel.getByText(/breach\(es\)/)).toHaveCount(0);
  await expect(panel.getByText(/1 rows/)).toHaveCount(0);
});

test("audit room snapshot empty state offers a snapshot button, not a CLI command", async ({
  page,
}) => {
  const posts: unknown[] = [];
  await page.route("**/api/v1/snapshots**", (route) => {
    if (route.request().method() === "POST") {
      posts.push(route.request().postDataJSON());
      return route.fulfill({
        status: 201,
        json: { data: { snapshot_path: "x", reason: "audit_request" } },
      });
    }
    return route.fulfill({ json: { data: [], meta: { count: 0 } } });
  });
  await page.goto("/console/audit-room/");
  await page.getByRole("tab", { name: "Snapshots" }).click();
  await expect(page.getByText(/--reason/)).toHaveCount(0);
  await page.getByRole("button", { name: "Take a snapshot" }).click();
  await expect.poll(() => posts.length).toBe(1);
});

test("AI governance strip uses plain gap labels and lists only AI assets", async ({
  page,
}) => {
  await page.goto("/console/ai-governance/");
  const strip = page.getByTestId("ai-governance-strip");
  await expect(strip).toBeVisible();
  await expect(strip.getByText(/ai\.model_inventory/)).toHaveCount(0);
  await expect(strip.getByText(/model\.lineage events/)).toHaveCount(0);
  // Models inferred from lineage are an inventory; no "missing" gap beside them.
  await expect(strip.getByText("No model inventory connected")).toHaveCount(0);
  await expect(strip.getByText(/golden:asset:soc2-/)).toHaveCount(0);
  // The golden fixture types assets by event, so nothing needs hiding.
  await expect(strip.getByText(/no AI inventory signals/)).toHaveCount(0);
});
