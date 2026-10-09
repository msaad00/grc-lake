import { expect, test, type Page } from "@playwright/test";

const TEMPLATES = [
  {
    template_id: "access-control",
    title: "Access Control Policy",
    category: "access_control",
    framework_ids: ["soc2"],
    related_control_ids: ["SOC2-CC6.1"],
    summary: "Who gets access and how it is reviewed.",
    variables: ["company_name"],
  },
  {
    template_id: "incident-response",
    title: "Incident Response Policy",
    category: "operations",
    framework_ids: ["soc2"],
    related_control_ids: ["SOC2-CC7.3"],
    summary: "How incidents are detected and handled.",
    variables: ["company_name"],
  },
];

const ADOPTED = {
  id: "pol-2",
  template_id: "incident-response",
  title: "Incident Response Policy",
  status: "draft",
  content: "# Incident Response Policy",
  variables: {},
  related_control_ids: ["SOC2-CC7.3"],
  owner: "security@company.com",
  created_by: "console",
  created_at: "2026-09-24T12:00:00Z",
  updated_at: "2026-09-24T12:00:00Z",
  published_at: null,
  review_due_at: null,
};

async function mockPolicies(page: Page, adoptBodies: unknown[]) {
  let adopted = false;
  await page.route("**/api/v1/policy-templates", (route) =>
    route.fulfill({ json: { data: TEMPLATES } }),
  );
  await page.route("**/api/v1/policies/coverage", (route) =>
    route.fulfill({
      json: {
        data: [
          {
            control_id: "SOC2-CC7.3",
            framework: "SOC 2",
            title: "Incident evaluation",
            template_ids: ["incident-response"],
            published: false,
            current: false,
            document_id: null,
            document_title: null,
            published_at: null,
            review_due_at: null,
          },
        ],
      },
    }),
  );
  await page.route("**/api/v1/policies/attestation-summary", (route) =>
    route.fulfill({
      json: {
        data: {
          published: 0,
          acknowledged: 0,
          unattested: 0,
          total_acknowledgments: 0,
        },
      },
    }),
  );
  await page.route("**/api/v1/policies/pol-2**", (route) => {
    if (route.request().url().includes("acknowledgments")) {
      return route.fulfill({ json: { data: [] } });
    }
    return route.fulfill({ json: { data: ADOPTED } });
  });
  await page.route(/\/api\/v1\/policies(\?.*)?$/, (route) => {
    if (route.request().method() === "POST") {
      adoptBodies.push(route.request().postDataJSON());
      adopted = true;
      return route.fulfill({ status: 201, json: { data: ADOPTED } });
    }
    const rows = adopted ? [ADOPTED] : [];
    return route.fulfill({
      json: { data: rows, meta: { count: rows.length } },
    });
  });
}

test("any policy template can be selected, adopted, and opened", async ({
  page,
}) => {
  const bodies: unknown[] = [];
  await mockPolicies(page, bodies);
  await page.goto("/console/policies/");

  const first = page.getByRole("button", { name: /^Access Control Policy/ });
  const second = page.getByRole("button", {
    name: /^Incident Response Policy/,
  });
  await expect(first).toHaveAttribute("aria-pressed", "true");
  await second.click();
  await expect(second).toHaveAttribute("aria-pressed", "true");
  await expect(first).toHaveAttribute("aria-pressed", "false");

  await page
    .getByRole("button", { name: "Adopt Incident Response Policy" })
    .click();
  await expect.poll(() => bodies.length).toBe(1);
  expect((bodies[0] as { template_id: string }).template_id).toBe(
    "incident-response",
  );
  await expect(page.locator("textarea")).toHaveValue(
    "# Incident Response Policy",
  );
});

test("a coverage gap offers the covering template", async ({ page }) => {
  await mockPolicies(page, []);
  await page.goto("/console/policies/");
  await page.getByRole("button", { name: "Adopt a covering policy" }).click();
  await expect(
    page.getByRole("button", { name: /^Incident Response Policy/ }).first(),
  ).toHaveAttribute("aria-pressed", "true");
  await expect(
    page.getByRole("button", { name: "Adopt Incident Response Policy" }),
  ).toBeVisible();
});

test("vendor risk validates the name, names templates, and guides the empty state", async ({
  page,
}) => {
  const posts: unknown[] = [];
  await page.route("**/api/v1/vendor-questionnaires", (route) =>
    route.fulfill({
      json: {
        data: [
          {
            template_id: "soc2-vendor-standard",
            name: "SOC 2 vendor standard",
            control_ids: [],
            framework_ids: ["soc2"],
            risk_domains: ["security"],
            safeguard_ids: [],
            mapping_status: "reviewed",
            mapped_question_count: 10,
            question_count: 10,
          },
        ],
      },
    }),
  );
  await page.route("**/api/v1/vendor-assessments**", (route) => {
    if (route.request().method() === "POST") {
      posts.push(route.request().postDataJSON());
    }
    return route.fulfill({ json: { data: [], meta: { count: 0 } } });
  });
  await page.goto("/console/vendor-risk/");

  await expect(page.getByText("No vendor assessments yet.")).toHaveCount(0);
  await expect(page.getByText(/Start your first vendor review/)).toBeVisible();
  const template = page.getByLabel("Template");
  await expect(template).toHaveValue("soc2-vendor-standard");
  await expect(template.locator("option:checked")).toHaveText(
    "SOC 2 vendor standard",
  );

  await page.getByRole("button", { name: "New assessment" }).click();
  await expect(page.getByText("Enter a vendor name.")).toBeVisible();
  await expect(page.getByLabel("Vendor name")).toHaveAttribute(
    "aria-invalid",
    "true",
  );
  expect(posts).toHaveLength(0);

  await page.getByRole("button", { name: "Start a vendor review" }).click();
  await expect(page.getByLabel("Vendor name")).toBeFocused();
});

const OIDC_UNCONFIGURED = {
  id: "oidc",
  label: "OIDC SSO",
  configured: false,
  login_url: "/auth/oidc/login",
  protocol: "OIDC",
  setup_hint: "Set GRC_LAKE_OIDC_ISSUER and client credentials.",
};

test("login page tells end users to ask their admin for SSO", async ({
  page,
}) => {
  await page.route("**/api/v1/auth/methods", (route) =>
    route.fulfill({
      json: {
        data: {
          require_auth: true,
          methods: [
            OIDC_UNCONFIGURED,
            {
              id: "api_key",
              label: "API key",
              configured: true,
              login_url: "",
              setup_hint: "Paste an API key.",
            },
          ],
        },
      },
    }),
  );
  await page.goto("/console/login/");
  await expect(page.getByText(/Ask your admin to enable SSO/)).toBeVisible();
  await expect(page.getByText(/environment variables/)).toHaveCount(0);
  await expect(page.getByText(/GRC_LAKE_OIDC_ISSUER/)).toHaveCount(0);
  await expect(
    page.getByRole("link", { name: /SSO setup guide/ }),
  ).toHaveAttribute("href", /docs\/SERVER_AUTH\.md$/);
});

test("auth page links unconfigured SSO to the setup guide; users panel hides env detail", async ({
  page,
}) => {
  await page.route("**/api/v1/auth/whoami", (route) =>
    route.fulfill({
      json: {
        data: {
          user_id: "u-1",
          tenant_id: "t-1",
          email: "admin@example.test",
          role: "admin",
          scopes: ["auth_admin"],
        },
      },
    }),
  );
  await page.route("**/api/v1/auth/methods", (route) =>
    route.fulfill({
      json: { data: { require_auth: true, methods: [OIDC_UNCONFIGURED] } },
    }),
  );
  await page.route("**/api/v1/auth/users", (route) =>
    route.fulfill({ json: { data: [], meta: { count: 0 } } }),
  );
  await page.goto("/console/auth/");

  await expect(page.getByRole("link", { name: "Setup guide" })).toHaveAttribute(
    "href",
    /docs\/SERVER_AUTH\.md$/,
  );
  await expect(page.getByText("No users yet")).toBeVisible();
  const envVar = page.getByText("GRC_LAKE_OIDC_ROLE_MAP");
  await expect(envVar).toBeHidden();
  await page.getByText("Details", { exact: true }).click();
  await expect(envVar).toBeVisible();
});

test("agents page links to key creation, shows a CI gate, and tucks env detail away", async ({
  page,
}) => {
  await page.goto("/console/agents/");
  await expect(page.getByRole("link", { name: "Create key" })).toHaveAttribute(
    "href",
    "/console/auth/#api-keys",
  );
  await expect(
    page.getByText(/uses: \.\/\.github\/actions\/posture-gate/),
  ).toBeVisible();
  await expect(page.getByText("GRC_LAKE_PUBLIC_URL")).toBeHidden();
});
