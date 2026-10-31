import { test } from "node:test";
import assert from "node:assert/strict";
import { classify, successful } from "../../../scripts/conformance/results.mjs";
test("Basic gate permits only reviewed optional skips and manual reviews", async () => {
  const { basicSuccessful } =
    await import("../../../scripts/conformance/basic/results.mjs");
  const profile = {
    modules: ["positive", "optional", "manual"],
    allowedSkips: ["optional"],
    allowedReviews: ["manual"],
  };
  const results = [
    {
      name: "positive",
      status: "FINISHED",
      result: "PASSED",
      outcome: "passed",
    },
    {
      name: "optional",
      status: "FINISHED",
      result: "SKIPPED",
      outcome: "skipped",
    },
    { name: "manual", status: "FINISHED", result: "REVIEW", outcome: "review" },
  ];
  assert.equal(basicSuccessful(results, profile), true);
  assert.equal(successful(results, 3), false);
  for (const result of ["SKIPPED", "REVIEW", "WARNING", "FAILED", "UNKNOWN"]) {
    const bad = [
      { ...results[0], result, outcome: classify("FINISHED", result) },
      ...results.slice(1),
    ];
    assert.equal(basicSuccessful(bad, profile), false);
  }
  assert.equal(basicSuccessful(results.slice(1), profile), false);
  assert.equal(
    basicSuccessful([results[0], results[0], results[2]], profile),
    false,
  );
  assert.equal(
    basicSuccessful(
      [...results.slice(0, 2), { ...results[2], status: "WAITING" }],
      profile,
    ),
    false,
  );
  assert.equal(
    basicSuccessful([], { modules: [], allowedSkips: [], allowedReviews: [] }),
    false,
  );
});
