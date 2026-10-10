import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";
import ts from "typescript";

// Render the actual component and persistence hook against a batched hook
// scheduler. No DOM is needed: the regression is two handlers from one render
// reading the same stale state before React flushes its queued updates.
function harness({ staleComponent = false, staleHook = false } = {}) {
  const states = [];
  const pending = [];
  const storage = new Map();
  let cursor = 0;
  const react = {
    useState(initial) {
      const slot = cursor++;
      if (!(slot in states)) states[slot] = initial;
      return [states[slot], (next) => pending.push(() => {
        states[slot] = typeof next === "function" ? next(states[slot]) : next;
      })];
    },
    useEffect() {},
    useCallback: (fn) => fn,
    useRef: () => ({ current: null }),
  };
  const jsx = (type, props) => ({ type, props });
  const modules = {
    react,
    "react/jsx-runtime": { jsx, jsxs: jsx },
    "next/navigation": { usePathname: () => "/dashboard" },
    "next/link": { default: "a" },
    "@radix-ui/react-dialog": {},
    "lucide-react": {},
    "./SidebarFooter": {},
    "@/lib/utils": { cn: () => "" },
    "@/lib/nav": { NAV_GROUPS: ["Assess", "Manage"], NAV_ITEMS: [], isActiveRoute: () => false },
  };
  function load(relative, transform = (s) => s) {
    const source = transform(readFileSync(new URL(relative, import.meta.url), "utf8"));
    const code = ts.transpileModule(source, { compilerOptions: {
      module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX,
      target: ts.ScriptTarget.ES2022,
    } }).outputText;
    const exports = {};
    vm.runInNewContext(code, {
      exports, require: (name) => {
        assert.ok(name in modules, `Unexpected dependency: ${name}`);
        return modules[name];
      },
      window: { localStorage: { getItem: (k) => storage.get(k) ?? null, setItem: (k, v) => storage.set(k, v) } },
    });
    return exports;
  }
  modules["@/lib/state/preferences"] = load("../src/lib/state/preferences.ts", (s) =>
    staleHook ? s.replace("next as (prev: T) => T)(prev)", "next as (prev: T) => T)(value)") : s);
  const { NavLinks } = load("../src/components/shell/Sidebar.tsx", (s) =>
    (staleComponent ? s.replace("setClosedGroups((prev) => ({ ...prev, [group]: !prev[group] }))",
      "setClosedGroups({ ...closedGroups, [group]: !closedGroups[group] })") : s) + "\nexport { NavLinks };\n");
  cursor = 0;
  const tree = NavLinks({ collapsed: false });
  const buttons = [];
  function walk(node) {
    if (Array.isArray(node)) return node.forEach(walk);
    if (!node || typeof node !== "object") return;
    if (node.type === "button") buttons.push(node.props.onClick);
    walk(node.props?.children);
  }
  walk(tree);
  assert.equal(buttons.length, 2);
  return { buttons, flush: () => {
    pending.splice(0).forEach((apply) => apply());
    return JSON.parse(storage.get("trustops:sidebar:closed-groups"));
  } };
}

test("two sidebar groups toggled in one batch retain both updates in storage", () => {
  const { buttons, flush } = harness();
  buttons[0](); buttons[1]();
  assert.deepEqual(flush(), { Assess: true, Manage: true });
});

test("two toggles of the same group cancel in one batch", () => {
  const { buttons, flush } = harness();
  buttons[0](); buttons[0]();
  assert.deepEqual(flush(), { Assess: false });
});

test("regression harness detects stale component and hook mutations", () => {
  for (const options of [{ staleComponent: true }, { staleHook: true }]) {
    const { buttons, flush } = harness(options);
    buttons[0](); buttons[1]();
    assert.notDeepEqual(flush(), { Assess: true, Manage: true });
  }
});
