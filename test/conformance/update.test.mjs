import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  discoverModules,
  moduleChanges,
  reviewedPlan,
  withoutComments,
} from "../../scripts/conformance/update.mjs";
const plan = "example-plan";
const sources = [
  `@PublishTestPlan(testPlanName = "example-plan", testModules = {
    First.class, // Disabled.class,
    /* AlsoDisabled.class, */ Second.class,
  }) public class Plan {}`,
  '@PublishTestModule(testName = "first-test", summary = "https://example.test/path") public class First {}',
  '@PublishTestModule(testName = "second-test") public class Second {}',
];
test("updater discovers literal official modules without enabling commented-out tests", () => {
  assert.deepEqual(discoverModules(sources, plan), [
    "first-test",
    "second-test",
  ]);
  assert.match(withoutComments(sources[1]), /https:\/\/example.test\/path/);
  for (const bad of [
    [],
    [...sources, sources[0]],
    sources.slice(0, 2),
    [
      sources[0].replace("First.class,", "First.class, First.class,"),
      ...sources.slice(1),
    ],
    [
      sources[0].replace("First.class,", 'System.getenv("MODULE"),'),
      ...sources.slice(1),
    ],
    [
      sources[0].replace('"example-plan"', '"different-plan"'),
      ...sources.slice(1),
    ],
  ])
    assert.throws(() => discoverModules(bad, plan));
});
test("changed module identities require review even if counts match", () => {
  const reviewed = ["first-test", "second-test"];
  assert.equal(reviewedPlan([...reviewed].reverse(), reviewed, 2), true);
  assert.equal(reviewedPlan(["first-test", "new-test"], reviewed, 2), false);
  assert.equal(
    reviewedPlan(["first-test", "second-test", "new-test"], reviewed, 3),
    false,
  );
  assert.equal(reviewedPlan(["first-test", "first-test"], reviewed, 2), false);
  assert.equal(reviewedPlan([], [], 0), false);
  assert.deepEqual(moduleChanges(reviewed, ["first-test", "new-test"]), {
    added: ["new-test"],
    removed: ["second-test"],
  });
});
test("reviewed manifest matches the pin and covers every negative response expectation", async () => {
  const pin = JSON.parse(
    await readFile("scripts/conformance/upstream.json", "utf8"),
  );
  const modules = JSON.parse(
    await readFile("scripts/conformance/federation/modules.json", "utf8"),
  );
  const { negativeReasons } =
    await import("../../scripts/conformance/federation/negative-checks.mjs");
  assert.equal(reviewedPlan(modules, modules, pin.expectedModules), true);
  for (const name of Object.keys(negativeReasons))
    assert.ok(modules.includes(name));
});

test("updater CLI pins a real checkout, preserves review decisions and is idempotent", async () => {
  const { mkdtemp, mkdir, writeFile, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join, resolve } = await import("node:path");
  const { execFileSync } = await import("node:child_process");
  const root = await mkdtemp(join(tmpdir(), "teraland-update-"));
  const suite = join(root, "upstream");
  const run = () =>
    JSON.parse(
      execFileSync(
        process.execPath,
        [resolve("scripts/conformance/update.mjs"), suite],
        {
          cwd: root,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
          env: { ...process.env, GITHUB_OUTPUT: join(root, "outputs") },
        },
      ),
    );
  try {
    await mkdir(join(root, "scripts/conformance/federation"), {
      recursive: true,
    });
    await mkdir(join(root, ".local"));
    await mkdir(join(suite, "src/main/java"), { recursive: true });
    for (const [index, source] of sources.entries())
      await writeFile(join(suite, `src/main/java/Source${index}.java`), source);
    const git = (args) =>
      execFileSync("git", ["-C", suite, ...args], { encoding: "utf8" }).trim();
    git(["init", "-q"]);
    git(["add", "."]);
    git([
      "-c",
      "user.name=Test",
      "-c",
      "user.email=test@example.invalid",
      "commit",
      "-qm",
      "Fixture",
    ]);
    const pinPath = join(root, "scripts/conformance/upstream.json");
    const manifestPath = join(
      root,
      "scripts/conformance/federation/modules.json",
    );
    await writeFile(
      pinPath,
      JSON.stringify({
        commit: "0".repeat(40),
        plan,
        expectedModules: 1,
        mongoImage: "unchanged",
      }),
    );
    const manifest = '["first-test"]\n';
    await writeFile(manifestPath, manifest);
    const first = run();
    assert.equal(first.changed, true);
    assert.deepEqual(first.added, ["second-test"]);
    const pin = JSON.parse(await readFile(pinPath, "utf8"));
    assert.equal(pin.commit, git(["rev-parse", "HEAD"]));
    assert.equal(pin.expectedModules, 2);
    assert.equal(pin.mongoImage, "unchanged");
    assert.equal(await readFile(manifestPath, "utf8"), manifest);
    assert.match(
      await readFile(join(root, ".local/conformance-update-pr.md"), "utf8"),
      /Added modules:\n- second-test/,
    );
    assert.equal(run().changed, false);
    await writeFile(join(suite, "src/main/java/Source0.java"), "changed");
    assert.throws(run);
    assert.deepEqual(JSON.parse(await readFile(pinPath, "utf8")), pin);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
