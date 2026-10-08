import { expect, test } from "@playwright/test";

// The graph routes serve one default-size page unless the caller follows
// meta.next_cursor. The mock pages in twos, smaller than anything the console
// asks for, so a console that reads one page shows 2 nodes, not 5.
const NODES = [
  {
    id: "framework:soc2",
    kind: "framework",
    label: "SOC 2",
    framework_id: "soc2",
  },
  {
    id: "control:SOC2-CC6.1",
    kind: "control",
    label: "CC6.1",
    framework_id: "soc2",
  },
  {
    id: "control:SOC2-CC7.2",
    kind: "control",
    label: "CC7.2",
    framework_id: "soc2",
  },
  { id: "evidence_type:okta.mfa", kind: "evidence_type", label: "okta.mfa" },
  {
    id: "asset:billing-db",
    kind: "asset",
    label: "Billing DB",
    asset_id: "asset-1",
  },
];
const EDGES = [
  {
    id: "e1",
    source: "framework:soc2",
    target: "control:SOC2-CC6.1",
    kind: "contains",
  },
  {
    id: "e2",
    source: "framework:soc2",
    target: "control:SOC2-CC7.2",
    kind: "contains",
  },
  {
    id: "e3",
    source: "control:SOC2-CC6.1",
    target: "evidence_type:okta.mfa",
    kind: "evidenced_by",
  },
  {
    id: "e4",
    source: "evidence_type:okta.mfa",
    target: "asset:billing-db",
    kind: "observed_on",
  },
];
const PAGE = 2;

test("the graph page follows next_cursor and renders every page", async ({
  page,
}) => {
  const requests: string[] = [];

  await page.route(/\/api\/v1\/graph(\?.*)?$/, async (route) => {
    const url = new URL(route.request().url());
    requests.push(url.search);
    const offset = Number(url.searchParams.get("cursor") ?? "0");
    const end = offset + PAGE;
    const longest = Math.max(NODES.length, EDGES.length);
    const nodes = NODES.slice(offset, end);
    const edges = EDGES.slice(offset, end);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        data: {
          nodes,
          edges,
          counts: { framework: 1, control: 2, evidence_type: 1, asset: 1 },
        },
        meta: {
          api_version: "v1",
          resource: "graph",
          count: longest,
          returned: nodes.length + edges.length,
          limit: PAGE,
          offset,
          next_cursor: end < longest ? String(end) : null,
          parts: {
            nodes: { count: NODES.length, returned: nodes.length },
            edges: { count: EDGES.length, returned: edges.length },
          },
        },
        errors: [],
      }),
    });
  });

  await page.goto("/console/graph/");
  await expect(page.getByText("5 nodes / 4 edges").first()).toBeVisible();
  expect(requests).toEqual([
    "?limit=1000",
    "?limit=1000&cursor=2",
    "?limit=1000&cursor=4",
  ]);
});
