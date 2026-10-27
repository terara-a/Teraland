import { readFile, writeFile, readdir } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

// Parse literal annotation values only. Upstream Java is data, never executed by
// the privileged updater. Unsupported source layouts require human attention.
export function withoutComments(source) {
  return source.replace(
    /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\/\*[\s\S]*?\*\/|\/\/[^\n]*/g,
    (token) => (token.startsWith("/") ? " " : token),
  );
}
export function discoverModules(sources, plan) {
  const clean = sources.map(withoutComments);
  const plans = clean.filter(
    (s) => /testPlanName\s*=\s*"([^"]+)"/.exec(s)?.[1] === plan,
  );
  if (plans.length !== 1)
    throw new Error("Expected exactly one literal upstream test plan");
  const list = /testModules\s*=\s*\{([^}]+)\}/.exec(plans[0])?.[1];
  if (!list || !/^\s*(?:[A-Za-z_$][\w$]*\.class\s*,?\s*)+$/.test(list))
    throw new Error("Unsupported upstream module list");
  const classes = [...list.matchAll(/([A-Za-z_$][\w$]*)\.class/g)].map(
    (m) => m[1],
  );
  const modules = classes.map((name) => {
    const matches = clean.filter((s) =>
      new RegExp(`\\bclass\\s+${name}\\b`).test(s),
    );
    const module =
      matches.length === 1 &&
      /testName\s*=\s*"([a-z0-9-]+)"/.exec(matches[0])?.[1];
    if (!module) throw new Error(`Missing literal test name for ${name}`);
    return module;
  });
  if (!modules.length || new Set(modules).size !== modules.length)
    throw new Error("Empty or duplicate upstream modules");
  return modules.sort();
}
export function moduleChanges(reviewed, discovered) {
  return {
    added: discovered.filter((n) => !reviewed.includes(n)),
    removed: reviewed.filter((n) => !discovered.includes(n)),
  };
}
export function reviewedPlan(actual, reviewed, expected) {
  return (
    Array.isArray(actual) &&
    actual.length === expected &&
    expected > 0 &&
    reviewed.length === expected &&
    new Set(actual).size === expected &&
    new Set(reviewed).size === expected &&
    actual.every((n) => reviewed.includes(n))
  );
}
async function javaSources(root) {
  const result = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) result.push(...(await javaSources(path)));
    else if (entry.isFile() && entry.name.endsWith(".java"))
      result.push(await readFile(path, "utf8"));
  }
  return result;
}
export async function update(suiteDir) {
  if (!suiteDir) throw new Error("Pass the upstream checkout directory");
  const pinPath = "scripts/conformance/upstream.json";
  const pin = JSON.parse(await readFile(pinPath, "utf8"));
  const reviewed = JSON.parse(
    await readFile("scripts/conformance/modules.json", "utf8"),
  );
  const revision = execFileSync("git", ["-C", suiteDir, "rev-parse", "HEAD"], {
    encoding: "utf8",
  }).trim();
  if (!/^[a-f0-9]{40}$/.test(revision)) throw new Error("Invalid upstream SHA");
  execFileSync("git", [
    "-C",
    suiteDir,
    "diff",
    "--exit-code",
    "HEAD",
    "--quiet",
  ]);
  const modules = discoverModules(
    await javaSources(join(suiteDir, "src/main/java")),
    pin.plan,
  );
  const changes = moduleChanges(reviewed, modules);
  const changed = revision !== pin.commit;
  const body =
    `Update the official OpenID Federation suite to ${revision}.\n\n` +
    `Upstream changes: https://github.com/openid-certification/conformance-suite/compare/${pin.commit}...${revision}\n\n` +
    `Official plan: ${pin.plan}\nModules: ${pin.expectedModules} → ${modules.length}\n\n` +
    `Added modules:\n${changes.added.map((n) => "- " + n).join("\n") || "- None"}\n\n` +
    `Removed modules:\n${changes.removed.map((n) => "- " + n).join("\n") || "- None"}\n\n` +
    `Federation RS256, PS256 and ES256 plus OIDC Basic validation is invoked explicitly by the daily updater, ` +
    `because GITHUB_TOKEN-created PRs do not trigger normal PR workflows. ` +
    `The Scheduled conformance validation check on this PR's head reports the result.\n\n` +
    `The reviewed module manifest and negative response expectations are intentionally not auto-approved. ` +
    `Module changes fail validation until reviewed. REVIEW remains manual review, not PASSED. ` +
    `Merge manually after checking upstream assertion/API/variant changes.\n`;
  await writeFile(".local/conformance-update-pr.md", body);
  if (changed)
    await writeFile(
      pinPath,
      JSON.stringify(
        { ...pin, commit: revision, expectedModules: modules.length },
        null,
        2,
      ) + "\n",
    );
  if (process.env.GITHUB_OUTPUT)
    await writeFile(
      process.env.GITHUB_OUTPUT,
      `changed=${changed}\nrevision=${revision}\n`,
      { flag: "a" },
    );
  console.log(
    JSON.stringify({
      changed,
      revision,
      expectedModules: modules.length,
      ...changes,
    }),
  );
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  await update(process.argv[2]);
