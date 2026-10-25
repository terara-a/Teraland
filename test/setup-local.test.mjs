import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, copyFile, readFile, rm, stat } from "node:fs/promises";
import { resolve, join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
const exec = promisify(execFile);

test("setup creates private config from a path containing spaces and URL-reserved characters without overwriting", async () => {
  const parent = resolve(".local");
  await mkdir(parent, { recursive: true });
  const dir = await mkdtemp(join(parent, "setup # "));
  try {
    const script = join(dir, "setup-local.mjs");
    await copyFile("scripts/setup-local.mjs", script);
    await exec(process.execPath, [script], { cwd: dir });
    const file = join(dir, ".dev.vars");
    const before = await readFile(file);
    assert.ok(before.includes("SIGNING_JWK="));
    assert.ok(before.includes("ENCRYPTION_JWK="));
    if (process.platform !== "win32")
      assert.equal((await stat(file)).mode & 0o777, 0o600);
    await assert.rejects(exec(process.execPath, [script], { cwd: dir }));
    assert.ok(
      before.equals(await readFile(file)),
      "existing credentials must be preserved",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
