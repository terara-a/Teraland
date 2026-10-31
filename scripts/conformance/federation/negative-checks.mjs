// Expectations match the 13 negative modules in the pinned upstream plan.
// Keep this audit independent of official status/result: REVIEW stays REVIEW.
const prefix = "openid-federation-automatic-client-registration-";
export const negativeReasons = Object.fromEntries(
  Object.entries({
    // Upstream also copies the changed client_id into the outer query.
    // The mismatch is therefore with the original iss, not the outer client_id.
    "invalid-client-id-in-request-object": "invalid_iss",
    "invalid-client-id-in-query-parameters": "invalid_client_id",
    "invalid-signature-on-request-object": "invalid_signature",
    "invalid-signature-with-other-keys-on-request-object": "invalid_signature",
    "invalid-request-object-exp": "invalid_exp",
    "invalid-request-object-iss": "invalid_iss",
    "invalid-request-object-aud": "invalid_aud",
    "invalid-request-object-sub": "forbidden_sub",
    "invalid-missing-request-object-jti": "invalid_jti",
    "invalid-missing-request-object-exp": "invalid_exp",
    "invalid-missing-request-object-iss": "invalid_iss",
    "invalid-missing-request-object-aud": "invalid_aud",
    "invalid-duplicate-request-object-jti": "replayed_jti",
  }).map(([name, reason]) => [prefix + name, reason]),
);
const reasons = new Set(Object.values(negativeReasons));
export async function observeAuthorization(response) {
  const body = await response.clone().text();
  const marker =
    /<p id="authorization-error" data-error="invalid_request_object" data-reason="([a-z_]+)">/.exec(
      body,
    );
  // Retain only fixed enums and booleans. Never persist URLs, headers, cookies,
  // JWTs, credentials or arbitrary response text, even when a check fails.
  return {
    status: response.status,
    html: response.headers.get("content-type")?.split(";")[0] === "text/html",
    reason: marker && reasons.has(marker[1]) ? marker[1] : null,
    noRedirect: !response.headers.has("location"),
    noCookie: !response.headers.has("set-cookie"),
    noForm: !/<form\b|<input\b/i.test(body),
    noCredentials:
      !/\b(?:code|access_token|id_token|request_uri)\s*["']?\s*[:=]/i.test(
        body,
      ),
    noStore: response.headers.get("cache-control") === "no-store",
    securePage:
      response.headers.get("content-security-policy") ===
        "default-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'" &&
      response.headers.get("referrer-policy") === "no-referrer" &&
      response.headers.get("x-content-type-options") === "nosniff",
  };
}
export function checkNegative(name, responses) {
  const expectedReason = negativeReasons[name];
  if (!expectedReason) return undefined;
  const replay = expectedReason === "replayed_jti";
  const rejection = responses.at(-1);
  return {
    expectedReason,
    responses,
    verified:
      responses.length === (replay ? 2 : 1) &&
      (!replay || responses[0].status === 200) &&
      rejection?.status === 400 &&
      rejection.html &&
      rejection.reason === expectedReason &&
      [
        "noRedirect",
        "noCookie",
        "noForm",
        "noCredentials",
        "noStore",
        "securePage",
      ].every((k) => rejection[k] === true),
  };
}
export function negativesSuccessful(results) {
  return Object.keys(negativeReasons).every((name) => {
    const matches = results.filter((r) => r.name === name);
    if (
      matches.length !== 1 ||
      !Array.isArray(matches[0].negativeCheck?.responses)
    )
      return false;
    return checkNegative(name, matches[0].negativeCheck.responses).verified;
  });
}
