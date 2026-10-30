export function classify(status, result) {
  if (result === "FAILED") return "failed";
  if (status !== "FINISHED") return "incomplete";
  switch (result) {
    case "PASSED":
      return "passed";
    case "FAILED":
      return "failed";
    case "REVIEW":
      return "review";
    case "WARNING":
      return "warning";
    case "SKIPPED":
      return "skipped";
    default:
      return "incomplete";
  }
}
export function successful(results, expected) {
  return (
    results.length === expected &&
    expected > 0 &&
    new Set(results.map((r) => r.name)).size === expected &&
    results.every((r) => r.outcome === "passed")
  );
}
// CI execution may finish successfully with manual reviews pending. This is
// deliberately separate from the strict conformance success above.
export function ciSuccessful(results, expected) {
  return (
    results.length === expected &&
    expected > 0 &&
    new Set(results.map((r) => r.name)).size === expected &&
    results.every(
      (r) =>
        r.status === "FINISHED" &&
        ["PASSED", "REVIEW"].includes(r.result) &&
        r.outcome === classify(r.status, r.result),
    )
  );
}
const xml = (s) =>
  String(s).replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&apos;",
      })[c],
  );
export function junit(results) {
  return `<?xml version="1.0" encoding="UTF-8"?><testsuite name="Official OpenID Federation OP" tests="${results.length}" failures="${results.filter((r) => r.outcome !== "passed").length}">${results.map((r) => `<testcase name="${xml(r.name)}">${r.outcome === "passed" ? "" : `<failure type="${xml(r.outcome)}" message="${xml(r.status + " / " + r.result)}"/>`}</testcase>`).join("")}</testsuite>\n`;
}

// Optional capabilities may be skipped only by the specific upstream modules
// that declare them optional. Preserve their original SKIPPED/REVIEW outcomes.
export function basicSuccessful(results, profile) {
  return (
    profile.modules.length > 0 &&
    new Set(profile.modules).size === profile.modules.length &&
    results.length === profile.modules.length &&
    new Set(results.map((r) => r.name)).size === profile.modules.length &&
    results.every(
      (r) =>
        profile.modules.includes(r.name) &&
        r.status === "FINISHED" &&
        r.outcome === classify(r.status, r.result) &&
        (r.result === "PASSED" ||
          (r.result === "SKIPPED" && profile.allowedSkips.includes(r.name)) ||
          (r.result === "REVIEW" && profile.allowedReviews.includes(r.name))),
    )
  );
}
