import { classify } from "../results.mjs";
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
