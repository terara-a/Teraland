import { test } from "node:test";
import assert from "node:assert/strict";
import {
  classify,
  successful,
  junit,
} from "../scripts/conformance/results.mjs";
test("official conformance gate requires every expected module to finish and pass", () => {
  const passed = {
    name: "test",
    status: "FINISHED",
    result: "PASSED",
    outcome: classify("FINISHED", "PASSED"),
  };
  assert.equal(successful([passed], 1), true);
  assert.equal(classify("INTERRUPTED", "FAILED"), "failed");
  assert.equal(successful([passed, passed], 2), false);
  for (const result of ["FAILED", "REVIEW", "WARNING", "SKIPPED", "UNKNOWN"]) {
    const r = { ...passed, result, outcome: classify("FINISHED", result) };
    assert.equal(successful([r], 1), false);
    assert.ok(junit([r]).includes("<failure"));
  }
  assert.equal(
    successful([{ ...passed, outcome: classify("WAITING", "PASSED") }], 1),
    false,
  );
  assert.equal(successful([], 0), false);
  assert.equal(successful([], 1), false);
  assert.equal(successful([passed], 20), false);
  assert.ok(
    junit([{ ...passed, name: 'x<&"', outcome: "failed" }]).includes(
      "x&lt;&amp;&quot;",
    ),
  );
});
