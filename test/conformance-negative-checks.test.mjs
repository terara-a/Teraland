import { test } from "node:test";
import assert from "node:assert/strict";
import {
  negativeReasons,
  observeAuthorization,
  checkNegative,
  negativesSuccessful,
} from "../scripts/conformance/negative-checks.mjs";
function response(reason, { body = "", headers = {}, status = 400 } = {}) {
  return new Response(
    `<p id="authorization-error" data-error="invalid_request_object" data-reason="${reason}">Rejected</p>${body}`,
    {
      status,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "Content-Security-Policy":
          "default-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        ...headers,
      },
    },
  );
}
test("negative audit requires all pinned scenarios and a successful first round for replay", async () => {
  const results = [];
  for (const [name, reason] of Object.entries(negativeReasons)) {
    const observations = [await observeAuthorization(response(reason))];
    if (reason === "replayed_jti") observations.unshift({ status: 200 });
    const negativeCheck = checkNegative(name, observations);
    assert.equal(negativeCheck.verified, true);
    assert.equal(checkNegative(name, []).verified, false);
    results.push({ name, negativeCheck });
  }
  assert.equal(negativesSuccessful(results), true);
  assert.equal(negativesSuccessful(results.slice(1)), false);
  assert.equal(negativesSuccessful([...results, results[0]]), false);
  const replay = results.find(
    (r) => r.negativeCheck.expectedReason === "replayed_jti",
  );
  assert.equal(
    checkNegative(replay.name, replay.negativeCheck.responses.slice(1))
      .verified,
    false,
  );
  assert.equal(checkNegative("unknown-module", []), undefined);
});
test("negative audit rejects generic errors, login forms, redirects and leaked credentials", async () => {
  const [name, reason] = Object.entries(negativeReasons)[0];
  for (const options of [
    { status: 200 },
    { status: 500 },
    { headers: { Location: "https://attacker.example" } },
    { headers: { "Set-Cookie": "secret=value" } },
    { headers: { "Content-Type": "application/json" } },
    { headers: { "Cache-Control": "public" } },
    { headers: { "Content-Security-Policy": "default-src *" } },
    { body: '<form><input name="password"></form>' },
    { body: '{"access_token":"private-token"}' },
    { body: "code=private-code" },
  ]) {
    const observation = await observeAuthorization(response(reason, options));
    assert.equal(checkNegative(name, [observation]).verified, false);
    assert.doesNotMatch(
      JSON.stringify(observation),
      /attacker|secret|private-token|private-code|password/,
    );
  }
  for (const badReason of ["invalid_signature", "unrecognized_private_value"]) {
    const observation = await observeAuthorization(response(badReason));
    assert.equal(checkNegative(name, [observation]).verified, false);
    assert.doesNotMatch(
      JSON.stringify(observation),
      /unrecognized_private_value/,
    );
  }
  const generic = await observeAuthorization(
    Response.json({ error: "invalid_request_object" }, { status: 400 }),
  );
  assert.equal(checkNegative(name, [generic]).verified, false);
});
