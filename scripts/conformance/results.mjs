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
