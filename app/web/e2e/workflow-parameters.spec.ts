import { expect, test } from "@playwright/test";

test("refresh updates selected node parameters without requiring reselection", async ({
  page,
}) => {
  let message = "Initial message";
  const workflow = () => ({
    workflow_id: "refresh-parameters",
    version: 1,
    name: "Parameter refresh",
    description: "Synthetic workflow",
    nodes: [
      { id: "shared-node", node_type: "test.message", params: { message } },
    ],
    edges: [],
    actor: "test",
    occurred_at: "2026-01-01T00:00:00Z",
    hash: "synthetic",
  });
  await page.route("**/api/v1/workflows?*", (route) =>
    route.fulfill({
      json: { data: [workflow()], meta: { count: 1 } },
    }),
  );
  await page.route("**/api/v1/workflows/actions?*", (route) =>
    route.fulfill({
      json: {
        data: [
          {
            node_type: "test.message",
            kind: "action",
            label: "Message",
            description: "Synthetic action",
            input_schema: {
              message: { type: "string", label: "Message text" },
            },
            output_schema: {},
          },
        ],
        meta: { count: 1 },
      },
    }),
  );
  await page.goto("/console/automation/");
  await page
    .getByRole("combobox", { name: "Select workflow" })
    .selectOption("refresh-parameters");
  const field = page.getByRole("textbox", { name: "Message text" });
  await expect(field).toHaveValue("Initial message");

  message = "Updated by another reviewer";
  await page.getByRole("button", { name: "Refresh data", exact: true }).click();
  await expect(field).toHaveValue(message);
  await field.fill("Local edit after refresh");
  await expect(field).toHaveValue("Local edit after refresh");

  await page.route("**/api/v1/workflows/actions/run", (route) =>
    route.fulfill({
      json: { data: { message: "tested" } },
    }),
  );
  const actionRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith("/api/v1/workflows/actions/run") &&
      request.method() === "POST",
  );
  await page.getByRole("button", { name: "Test action", exact: true }).click();
  expect((await actionRequest).postDataJSON().params).toEqual({
    message: "Local edit after refresh",
  });

  await page.route("**/api/v1/workflows", (route) =>
    route.fulfill({
      json: { data: workflow() },
    }),
  );
  const saveRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith("/api/v1/workflows") &&
      request.method() === "POST",
  );
  await page.getByRole("heading", { level: 1, name: "Workflows" }).click();
  await page.keyboard.press("ControlOrMeta+s");
  expect((await saveRequest).postDataJSON().nodes[0].params).toEqual({
    message: "Local edit after refresh",
  });
});
