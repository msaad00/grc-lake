import { expect, test, type Page } from "@playwright/test";

// Keep response fixtures authoritative; live stream payloads otherwise replace
// the query data while testing these isolated UI decisions.
test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/stream", (route) =>
    route.fulfill({ status: 200, contentType: "text/event-stream", body: "" }),
  );
});

async function mockAi(page: Page, observed = 1, catalogued = 10) {
  await page.route("**/api/v1/platform/ai-governance", (r) =>
    r.fulfill({
      json: {
        data: {
          state: "needs_work",
          governance_score: 100,
          frameworks_ready: 0,
          frameworks_total: 1,
          inventory: {
            total: 1,
            models: 1,
            agents: 0,
            with_model_card: 1,
            with_lineage: 1,
          },
          events: {
            model_inventory: 1,
            model_lineage: 1,
            agent_runtime: 0,
            repo_artifacts: 1,
          },
          artifacts: { model_cards: 1 },
          evidence_loops: {},
          gaps: [],
          aibom: { shipped: true, note: "" },
          frameworks: [
            {
              framework_id: "nist_ai_rmf",
              label: "Test AI framework",
              requirements: catalogued,
              mapped_requirements: 8,
              controls_with_evidence: observed,
              evaluated_control_count: observed,
              catalog_control_count: catalogued,
              coverage_sufficient:
                catalogued > 0 && observed / catalogued >= 0.5,
              passing_controls: observed,
              failing_controls: 0,
              score: 100,
            },
          ],
        },
      },
    }),
  );
  await page.route("**/api/v1/platform/ai-governance/inventory**", (r) =>
    r.fulfill({ json: { data: [] } }),
  );
}

async function review(
  page: Page,
  options: {
    scopes?: string[];
    auth?: string;
    status?: string;
    decision?: string;
  } = {},
) {
  const campaign = {
    id: "review1",
    name: "Quarterly review",
    scope: "all",
    status: options.status ?? "active",
    due_at: null,
  };
  await page.route("**/api/v1/auth/whoami", (r) =>
    r.fulfill({
      json: {
        data: {
          user_id: "reviewer",
          email: "reviewer@example.test",
          scopes: options.scopes ?? ["read", "control_manage"],
          auth_method: options.auth ?? "session:oidc",
        },
      },
    }),
  );
  await page.route("**/api/v1/access-reviews**", (r) => {
    const path = new URL(r.request().url()).pathname;
    if (r.request().method() !== "GET")
      return r.fulfill({
        status: 400,
        json: { errors: [{ detail: "Campaign has pending decisions" }] },
      });
    const data = path.endsWith("/coverage")
      ? []
      : path.endsWith("/items")
        ? [
            {
              id: "item1",
              subject_id: "someone",
              subject_name: "Other user",
              source: "okta",
              decision: options.decision ?? "pending",
            },
          ]
        : path.endsWith("/review1")
          ? {
              ...campaign,
              progress: {
                total: 1,
                pending: 1,
                certified: 0,
                revoked: 0,
                flagged: 0,
              },
            }
          : [campaign];
    return r.fulfill({ json: { data } });
  });
  await page.goto("/console/access-reviews/");
  await page.getByRole("button", { name: /Quarterly review/ }).click();
}

test("read-only review controls explain permission and cannot mutate", async ({
  page,
}) => {
  await review(page, { scopes: ["read"] });
  await expect(
    page.getByRole("button", { name: "New campaign", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Mark completed" }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Seed from evidence" }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "certified", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByText(/Your role can view access reviews/).first(),
  ).toBeVisible();
});

for (const status of ["draft", "completed", "cancelled"]) {
  test(`${status} campaign cannot record a decision`, async ({ page }) => {
    await review(page, { status });
    await expect(
      page.getByRole("button", { name: "certified", exact: true }),
    ).toBeDisabled();
    if (status !== "draft")
      await expect(
        page.getByRole("button", { name: "Seed from evidence" }),
      ).toBeDisabled();
    await expect(
      page.getByText(
        /Decisions require an active campaign|This campaign is closed/,
      ),
    ).toBeVisible();
  });
}

test("recorded review decisions cannot be changed", async ({ page }) => {
  await review(page, { decision: "certified" });
  await expect(
    page.getByRole("button", { name: "flagged", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByText("Recorded decisions cannot be changed."),
  ).toBeVisible();
});

test("human review requirement is inline and write failures are visible", async ({
  page,
}) => {
  await review(page, { auth: "api_key" });
  await expect(
    page.getByRole("button", { name: "certified", exact: true }),
  ).toBeDisabled();
  await expect(page.getByText(/Sign in with OIDC or SAML/)).toBeVisible();
  await page.getByRole("button", { name: "Mark completed" }).click();
  await expect(
    page
      .getByRole("alert")
      .filter({ hasText: "Campaign has pending decisions" }),
  ).toBeVisible();
});

test("AI governance reports observed denominators and weighted score meaning", async ({
  page,
}) => {
  await mockAi(page);
  await page.goto("/console/ai-governance/");
  const strip = page.getByTestId("ai-governance-strip");
  await expect(strip.getByText(/55% inventory.*45%/)).toBeVisible();
  await expect(
    strip.getByText(/passing.*observed.*catalogued/).first(),
  ).toBeVisible();
});

test("assessment wording distinguishes lake evaluation from live provider proof", async ({
  page,
}) => {
  await page.goto("/console/dashboard/");
  await expect(
    page.getByRole("heading", { name: "Latest lake assessment", exact: true }),
  ).toBeAttached();
});

for (const [observed, catalogued] of [
  [1, 10],
  [5, 10],
  [8, 10],
  [1, 0],
]) {
  test(`AI framework shows coverage for ${observed} of ${catalogued} observed controls`, async ({
    page,
  }) => {
    await mockAi(page, observed, catalogued);
    await page.goto("/console/ai-governance/");
    const strip = page.getByTestId("ai-governance-strip");
    await expect(
      strip.getByText(
        `${observed}/${observed} passing · ${observed}/${catalogued || "unknown"} observed / catalogued`,
      ),
    ).toBeVisible();
    if (!catalogued || observed / catalogued < 0.5) {
      await expect(
        strip.getByText("Insufficient coverage", { exact: true }),
      ).toBeVisible();
      await expect(
        strip.getByText("100% passing", { exact: true }),
      ).toHaveCount(0);
    } else
      await expect(
        strip.getByText("100% passing", { exact: true }),
      ).toBeVisible();
  });
}

test("revoking a public share requires confirmation", async ({ page }) => {
  let writes = 0;
  await page.route("**/api/v1/trust-shares**", (r) => {
    if (r.request().method() === "POST") {
      writes++;
      return r.fulfill({ json: { data: { revoked: true } } });
    }
    return r.fulfill({
      json: {
        data: [
          {
            share_id: "share1",
            role: "auditor",
            sensitivity_ceiling: "public",
            created_by: "owner",
            created_at: "2026-10-06T00:00:00Z",
            expires_at: "2030-10-06T00:00:00Z",
            token_sha256: "a".repeat(64),
            revoked_at: null,
          },
        ],
      },
    });
  });
  await page.goto("/console/trust-center/");
  await page.evaluate(() => {
    window.confirm = () => false;
  });
  await page.getByRole("button", { name: "Revoke", exact: true }).click();
  await page.waitForTimeout(200);
  expect(writes).toBe(0);
  await page.evaluate(() => {
    window.confirm = () => true;
  });
  await page.getByRole("button", { name: "Revoke", exact: true }).click();
  await expect.poll(() => writes).toBe(1);
});

test("deleting a saved view requires confirmation", async ({ page }) => {
  let writes = 0;
  await page.route("**/api/v1/saved-views**", (r) => {
    if (r.request().method() === "DELETE") {
      writes++;
      return r.fulfill({ json: { data: { deleted: true } } });
    }
    return r.fulfill({
      json: {
        data: [
          {
            id: "view1",
            name: "My evidence",
            filters: {},
            surface: "evidence",
          },
        ],
      },
    });
  });
  await page.goto("/console/evidence/");
  await page.evaluate(() => {
    window.confirm = () => false;
  });
  await page.getByRole("button", { name: "Delete saved view" }).click();
  await page.waitForTimeout(200);
  expect(writes).toBe(0);
  await page.evaluate(() => {
    window.confirm = () => true;
  });
  await page.getByRole("button", { name: "Delete saved view" }).click();
  await expect.poll(() => writes).toBe(1);
});

test("read-only users cannot issue shares or save views", async ({ page }) => {
  await page.route("**/api/v1/auth/whoami", (r) =>
    r.fulfill({
      json: {
        data: {
          user_id: "reader",
          email: "reader@example.test",
          scopes: ["read"],
        },
      },
    }),
  );
  await page.goto("/console/trust-center/");
  await expect(
    page.getByRole("button", { name: "Issue share", exact: true }),
  ).toBeDisabled();
  await expect(page.getByText(/Your role can view shares/)).toBeVisible();
  await page.goto("/console/evidence/");
  await expect(
    page.getByRole("button", { name: "Save current", exact: true }),
  ).toBeDisabled();
});

test("authorized human can review a pending item in an active campaign", async ({
  page,
}) => {
  await review(page);
  await expect(
    page.getByRole("button", { name: "certified", exact: true }),
  ).toBeEnabled();
  await expect(
    page.getByRole("button", { name: "Seed from evidence" }),
  ).toBeEnabled();
});

for (const synthetic of [true, false]) {
  test(`assessment labels synthetic provenance only when explicitly ${synthetic}`, async ({
    page,
  }) => {
    await page.route("**/api/v1/posture/current", async (route) => {
      const response = await route.fetch();
      const body = await response.json();
      body.data.synthetic_fixture = synthetic;
      await route.fulfill({ response, json: body });
    });
    await page.goto("/console/dashboard/");
    const notice = page.getByText(
      "Contains synthetic demonstration evidence; synthetic rows are not production proof.",
      { exact: true },
    );
    await expect(
      page.getByRole("region", { name: "Latest lake assessment" }),
    ).toBeVisible();
    if (synthetic) await expect(notice).toBeVisible();
    else await expect(notice).toHaveCount(0);
  });
}
