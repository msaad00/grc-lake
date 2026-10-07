import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import test from "node:test";

const require = createRequire(import.meta.url);
// Check the copies actually resolved by both consumers, including nested installs.
const paths = new Set([
  createRequire(require.resolve("micromatch")).resolve("braces"),
  createRequire(require.resolve("chokidar")).resolve("braces"),
]);
const nested = (depth, open = "{", close = "}") =>
  open.repeat(depth) + "a" + close.repeat(depth);
const depthError = /exceeds max depth/;

for (const path of paths) {
  const braces = require(path);

  for (const method of ["parse", "compile", "expand", "stringify"]) {
    for (const [open, close] of [["{", "}"], ["(", ")"]]) {
      test(`${method}: ${open}${close} nesting admits 100 and rejects 101`, () => {
        assert.doesNotThrow(() => braces[method](nested(100, open, close)));
        assert.throws(() => braces[method](nested(101, open, close)), depthError);
        assert.throws(
          () => braces[method](nested(101, open, close), { maxDepth: Infinity }),
          depthError,
        );
      });
    }
  }

  test("deep input is rejected before stack exhaustion in a small-stack process", () => {
    const child = spawnSync(process.execPath, ["--stack_size=512", "-e", `
      const assert = require('node:assert/strict');
      const braces = require(${JSON.stringify(path)});
      for (const method of ['parse', 'compile', 'expand', 'stringify']) {
        for (const [open, close] of [['{', '}'], ['(', ')']]) {
          const input = open.repeat(4000) + 'a' + close.repeat(4000);
          assert.throws(() => braces[method](input), /exceeds max depth/);
        }
      }
    `], { timeout: 5000, encoding: "utf8" });
    assert.equal(child.error, undefined, child.error?.message);
    assert.equal(child.status, 0, child.stderr);
  });

  for (const method of ["compile", "expand", "stringify"]) {
    test(`${method}: direct AST cannot bypass the parser limit`, () => {
      let node = { type: "text", value: "a" };
      for (let i = 0; i < 101; i++) node = { type: "brace", nodes: [node] };
      assert.throws(() => braces[method]({ type: "root", nodes: [node] }), depthError);
    });
  }

  test("lower and fractional limits are enforced and cannot raise the hard cap", () => {
    assert.doesNotThrow(() => braces.parse("{a,b}", { maxDepth: 1.5 }));
    assert.throws(() => braces.parse("{{a,b},c}", { maxDepth: 1.5 }), depthError);
    assert.throws(() => braces.parse(nested(101), { maxDepth: 10000 }), depthError);
  });

  test("ordinary alternatives, ranges, escapes, and stringify behavior are retained", () => {
    assert.deepEqual(braces.expand("src/*.{js,ts}"), ["src/*.js", "src/*.ts"]);
    assert.deepEqual(braces.expand("file{1..3}.ts"), ["file1.ts", "file2.ts", "file3.ts"]);
    assert.deepEqual(braces.expand("foo/({a,b})"), ["foo/(a)", "foo/(b)"]);
    assert.deepEqual(braces.expand(String.raw`\{a,b\}`), ["{a,b}"]);
    for (const input of ["{{a}}", "{a,{b}}", "{{x}y}", "{a,{b,{c}}", "{}{a}"]) {
      assert.equal(braces.stringify(braces.parse(input), { escapeInvalid: true }), input);
    }
  });
}
