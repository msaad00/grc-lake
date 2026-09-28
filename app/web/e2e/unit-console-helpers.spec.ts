import { expect, test } from "@playwright/test";
import {
  packState,
  splitFrameworkPacks,
  stubCountLabel,
  stubStatusLabel,
} from "../src/lib/framework-packs";
import { joinList } from "../src/lib/format";
import { displayLabel } from "../src/lib/display";
import { MAPPING_REVIEW_GLOSSARY } from "../src/lib/console-copy";

// Pure-function checks for shared console helpers; no browser page needed.

test.describe("framework pack counts", () => {
  const registry = [
    { framework_id: "soc2", control_count: 61, superseded_by: null },
    { framework_id: "soc1", control_count: 0, superseded_by: null },
    {
      framework_id: "iso-27701-2019",
      control_count: 0,
      superseded_by: "iso-27701-2025",
    },
    {
      framework_id: "iso-27701-2025",
      control_count: 10,
      superseded_by: null,
    },
  ];

  test("counts only entries with seeded requirements as packs", () => {
    const { packs, stubs } = splitFrameworkPacks(registry);
    expect(packs.map((row) => row.framework_id)).toEqual([
      "soc2",
      "iso-27701-2025",
    ]);
    expect(stubs.map((row) => row.framework_id)).toEqual([
      "soc1",
      "iso-27701-2019",
    ]);
    expect(stubCountLabel(stubs.length)).toBe("2 planned or superseded");
    expect(stubCountLabel(0)).toBe("");
  });

  test("the API pack_state wins over the fallback rule", () => {
    expect(packState({ pack_state: "planned", control_count: 5 })).toBe(
      "planned",
    );
    expect(packState({ seeded_control_count: 3 })).toBe("seeded");
  });

  test("a superseded stub names its successor", () => {
    const names = new Map([["iso-27701-2025", "ISO/IEC 27701:2025"]]);
    expect(stubStatusLabel(registry[2], names)).toBe(
      "Superseded by ISO/IEC 27701:2025",
    );
    expect(stubStatusLabel(registry[1], names)).toBe(
      "Planned · no requirements catalogued",
    );
  });
});

test.describe("list join", () => {
  test("joins names in plain English", () => {
    expect(joinList([])).toBe("");
    expect(joinList(["Snowflake"])).toBe("Snowflake");
    expect(joinList(["ClickHouse", "Snowflake"], "or")).toBe(
      "ClickHouse or Snowflake",
    );
    expect(joinList(["BigQuery", "Iceberg"])).toBe("BigQuery and Iceberg");
    expect(joinList(["A", "B", "C"], "or")).toBe("A, B, or C");
  });
});

test.describe("status display map", () => {
  test("never shows raw enums", () => {
    expect(displayLabel("critical")).toBe("Critical");
    expect(displayLabel("disabled")).toBe("Disabled");
    expect(displayLabel("in_progress")).toBe("In progress");
    expect(displayLabel("never_pulled")).toBe("Never pulled");
    expect(displayLabel("action_required")).toBe("Action required");
    expect(displayLabel("needs_changes")).toBe("Needs changes");
    expect(displayLabel("")).toBe("");
    expect(displayLabel(null)).toBe("");
  });
});

test.describe("mapping review glossary", () => {
  test("one label and definition per review state", () => {
    expect(Object.keys(MAPPING_REVIEW_GLOSSARY).sort()).toEqual([
      "maintainer_reviewed",
      "needs_changes",
      "org_reviewed",
      "proposed",
      "rejected",
    ]);
    expect(MAPPING_REVIEW_GLOSSARY.org_reviewed.label).toBe("Org-reviewed");
    for (const entry of Object.values(MAPPING_REVIEW_GLOSSARY))
      expect(entry.definition.length).toBeGreaterThan(10);
    expect(displayLabel("maintainer_reviewed")).toBe("Maintainer-reviewed");
  });
});
