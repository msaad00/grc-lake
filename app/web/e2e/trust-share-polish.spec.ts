import { expect, test, type Page } from "@playwright/test";

const ISSUED = {
  share_id: "shr_abc",
  role: "auditor",
  scope: "posture_full",
  framework_id: null,
  sensitivity_ceiling: "public",
  expires_at: "2026-09-25T12:00:00.123456Z",
  created_by: "console",
  created_at: "2026-09-24T12:00:00.123456Z",
  revoked_at: null,
  token_sha256: "a".repeat(64),
  token: "trust_tok123",
};

async function mockShares(page: Page, bodies: Array<Record<string, unknown>>) {
  await page.route("**/api/v1/trust-shares**", async (route) => {
    const req = route.request();
    if (req.method() === "POST") {
      const body = req.postDataJSON() as Record<string, unknown>;
      bodies.push(body);
      return route.fulfill({
        status: 201,
        json: {
          data: {
            ...ISSUED,
            sensitivity_ceiling: body.sensitivity_ceiling ?? "public",
          },
        },
      });
    }
    return route.fulfill({ json: { data: [], meta: { count: 0 } } });
  });
}

test("trust center issues a share for the chosen audience with a copyable link", async ({
  page,
}) => {
  const bodies: Array<Record<string, unknown>> = [];
  await mockShares(page, bodies);
  await page.goto("/console/trust-center/");

  await expect(page.getByText("posture_full")).toHaveCount(0);
  await expect(page.getByText(/capped at public summary/)).toHaveCount(0);
  await expect(page.getByText("TENANT_INTERNAL")).toHaveCount(0);
  await expect(page.getByText("tenant_internal")).toHaveCount(0);

  const customer = page.getByRole("button", { name: /Customer trust/ });
  const auditor = page.getByRole("button", { name: /Auditor review/ });
  await expect(customer).toHaveAttribute("aria-pressed", "true");
  await auditor.click();
  await expect(auditor).toHaveAttribute("aria-pressed", "true");
  await expect(customer).toHaveAttribute("aria-pressed", "false");

  await page.getByRole("button", { name: "Issue share" }).click();
  await expect.poll(() => bodies.length).toBe(1);
  expect(bodies[0].sensitivity_ceiling).toBe("internal");

  const origin = new URL(page.url()).origin;
  const link = `${origin}/console/trust/trust_tok123`;
  await expect(page.getByText(link, { exact: true })).toBeVisible();
  const preview = page.getByRole("link", { name: "Open preview" });
  await expect(preview).toHaveAttribute("href", link);
  await expect(preview).toHaveAttribute("target", "_blank");
  await expect(page.getByText(/\.123456/)).toHaveCount(0);
  await expect(page.getByText("shr_abc", { exact: true })).toHaveCount(0);

  await customer.click();
  await page.getByRole("button", { name: "Issue share" }).click();
  await expect.poll(() => bodies.length).toBe(2);
  expect(bodies[1].sensitivity_ceiling).toBe("public");
});

const SUMMARY = {
  schema_version: "trustops.public_trust.v1",
  data_residency:
    "evidence never leaves this lake; only this summary is shared",
  issued_by: "Acme Security",
  scope: "posture_full",
  role: "auditor",
  sensitivity_ceiling: "public",
  detail_level: "summary",
  expires_at: "2026-09-30T12:00:00.123456Z",
  evaluated_at: "2026-09-24T09:30:00.654321Z",
  posture: {
    score: 6.05,
    state: "critical",
    framework_count: 2,
    control_count: 120,
  },
  frameworks: [
    {
      framework: "ISO 27001:2022",
      score: 61.4789,
      state: "attention_required",
      control_count: 93,
    },
    { framework: "SOC 2", score: 97, state: "ready", control_count: 27 },
  ],
};

test("public trust view shows human status, not raw counts, at summary level", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route("**/api/public/trust/**", (route) =>
    route.fulfill({ json: SUMMARY }),
  );
  await page.goto("/console/trust/trust_tok123");

  await expect(page.getByText("ISO 27001:2022")).toBeVisible();
  await expect(page.getByText("In progress").first()).toBeVisible();
  await expect(page.getByText("Ready", { exact: true })).toBeVisible();
  await expect(page.getByText("attention_required")).toHaveCount(0);
  await expect(page.getByText("critical", { exact: true })).toHaveCount(0);
  await expect(page.getByText("6.05")).toHaveCount(0);
  await expect(page.getByText("61.4789")).toHaveCount(0);
  await expect(page.getByText("Open violations")).toHaveCount(0);
  await expect(page.getByText("Stale controls")).toHaveCount(0);
  await expect(page.getByText(/\.654321|\.123456/)).toHaveCount(0);
  await expect(page.getByText(/Last verified/)).toBeVisible();

  const name = page.getByText("ISO 27001:2022");
  const score = page.getByTestId("framework-score").first();
  const [nameBox, scoreBox] = await Promise.all([
    name.boundingBox(),
    score.boundingBox(),
  ]);
  expect(nameBox && scoreBox).toBeTruthy();
  const overlaps =
    nameBox!.x < scoreBox!.x + scoreBox!.width &&
    nameBox!.x + nameBox!.width > scoreBox!.x &&
    nameBox!.y < scoreBox!.y + scoreBox!.height &&
    nameBox!.y + nameBox!.height > scoreBox!.y;
  expect(overlaps).toBe(false);
  const scrollWidth = await page.evaluate(
    () => document.documentElement.scrollWidth,
  );
  expect(scrollWidth).toBeLessThanOrEqual(390);
});

test("public trust view follows the light theme instead of a fixed dark canvas", async ({
  page,
}) => {
  await page.emulateMedia({ colorScheme: "light" });
  await page.route("**/api/public/trust/**", (route) =>
    route.fulfill({ json: SUMMARY }),
  );
  await page.goto("/console/trust/trust_tok123");
  const card = page.getByTestId("trust-posture-card");
  await expect(card).toBeVisible();
  const bg = await card.evaluate((el) => getComputedStyle(el).backgroundColor);
  expect(bg).toBe("rgb(255, 255, 255)");
});

test("public trust view shows defect counts only for detailed shares", async ({
  page,
}) => {
  await page.route("**/api/public/trust/**", (route) =>
    route.fulfill({
      json: {
        ...SUMMARY,
        sensitivity_ceiling: "internal",
        detail_level: "detailed",
        posture: {
          ...SUMMARY.posture,
          open_violation_count: 19,
          critical_violation_count: 2,
          high_violation_count: 5,
          stale_control_count: 38,
        },
      },
    }),
  );
  await page.goto("/console/trust/trust_tok123");
  await expect(page.getByText("Open violations")).toBeVisible();
  await expect(page.getByText("Stale controls")).toBeVisible();
});

test("partial public evidence shows the evaluated catalog denominator", async ({
  page,
}) => {
  await page.route("**/api/public/trust/**", (route) =>
    route.fulfill({
      json: {
        ...SUMMARY,
        posture: {
          score: 100,
          state: "partial_evidence",
          framework_count: 1,
          control_count: 1,
        },
        frameworks: [
          {
            framework: "SOC 2",
            score: 100,
            state: "partial_evidence",
            control_count: 1,
            evaluated_control_count: 1,
            catalog_control_count: 61,
            coverage_ratio: 1 / 61,
          },
        ],
      },
    }),
  );
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/console/trust/trust_tok123");
  await expect(page.getByText("Partial evidence").first()).toBeVisible();
  await expect(
    page.getByText("1 / 61 catalog controls evaluated"),
  ).toBeVisible();
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(390);
  await page.screenshot({
    path: test.info().outputPath("partial-evidence.png"),
    fullPage: true,
  });
  await expect(page.getByText("Observed evidence score")).toBeVisible();
  await expect(page.getByText("Ready", { exact: true })).toHaveCount(0);
});
