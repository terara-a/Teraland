import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { jwtVerify, createLocalJWKSet } from "jose";
import { privateJWK } from "../scripts/setup-local.mjs";
const issuer = "https://op.example",
  redirect = "https://app.example/callback?registered=1",
  id = "web-app",
  secret = "test-only-client-secret-".repeat(2);
let mf, dir, bindings;
let outbound = 0;
const options = (override = {}) => ({
  ...convertV4MiniflareOptions({
    name: "basic-tests",
    scriptPath: ".build/index.js",
    modules: true,
    compatibilityDate: "2026-10-01",
    durableObjects: { STATE: { className: "ProviderState", useSQLite: true } },
    bindings: { ...bindings, ...override },
    outboundService: () => {
      outbound++;
      return new Response("Unexpected outbound", { status: 500 });
    },
  }),
  resourcePersistencePath: dir,
});
before(async () => {
  const [signing, encryption] = await Promise.all([
    privateJWK("RS256", "sig"),
    privateJWK("RSA-OAEP-256", "enc"),
  ]);
  dir = await mkdtemp(join(tmpdir(), "teraland-basic-"));
  bindings = {
    ISSUER: issuer,
    SIGNING_JWK: JSON.stringify(signing),
    ENCRYPTION_JWK: JSON.stringify(encryption),
    TERALAND_USERNAME: "alice",
    TERALAND_PASSWORD: "test-password-for-basic",
    FEDERATION_HOSTS: "[]",
    TRUST_ANCHORS: "{}",
    STATIC_CLIENTS: JSON.stringify([
      { client_id: id, client_secret: secret, redirect_uris: [redirect] },
      {
        client_id: "other-app",
        client_secret: secret,
        redirect_uris: [redirect],
      },
    ]),
    USER_CLAIMS: JSON.stringify({
      name: "Alice",
      email: "alice@example.test",
      email_verified: true,
    }),
  };
  mf = new Miniflare(options());
  await mf.ready;
});
after(async () => {
  await mf?.dispose();
  await rm(dir, { recursive: true, force: true });
  assert.equal(outbound, 0);
});
async function request(path, params, headers = {}) {
  return mf.dispatchFetch(issuer + path, {
    redirect: "manual",
    ...(params
      ? {
          method: "POST",
          body: new URLSearchParams(params).toString(),
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            ...headers,
          },
        }
      : { headers }),
  });
}
const params = (extra = {}) => ({
  client_id: id,
  redirect_uri: redirect,
  response_type: "code",
  scope: "openid",
  state: "state-preserved",
  nonce: "nonce-preserved",
  ...extra,
});
async function authorize(extra = {}, cookie = "", post = false) {
  const p = params(extra);
  return post
    ? request("/authorize", p, { cookie })
    : request("/authorize?" + new URLSearchParams(p), null, { cookie });
}
async function loginPage(response) {
  assert.equal(response.status, 200, await response.clone().text());
  const html = await response.text();
  return {
    request_id: /name="request_id" value="([^"]+)"/.exec(html)[1],
    cookie: response.headers.getSetCookie()[0].split(";")[0],
  };
}
async function login(page) {
  return request(
    "/login",
    {
      request_id: page.request_id,
      username: "alice",
      password: "test-password-for-basic",
    },
    { cookie: page.cookie, origin: issuer },
  );
}
function codeFrom(response) {
  assert.equal(response.status, 303);
  const u = new URL(response.headers.get("location"));
  assert.equal(u.origin, "https://app.example");
  assert.equal(u.searchParams.get("registered"), "1");
  assert.equal(u.searchParams.get("state"), "state-preserved");
  assert.equal(u.searchParams.get("iss"), issuer);
  assert.ok(u.searchParams.get("code"));
  return u.searchParams.get("code");
}
async function grant(extra = {}, post = false) {
  const r = await login(await loginPage(await authorize(extra, "", post)));
  return {
    code: codeFrom(r),
    cookie: r.headers
      .getSetCookie()
      .find((c) => c.startsWith("teraland_session="))
      .split(";")[0],
  };
}
async function redeem(code, method = "basic", extra = {}, headers = {}) {
  return request(
    "/token",
    {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirect,
      ...(method === "post" ? { client_id: id, client_secret: secret } : {}),
      ...extra,
    },
    {
      ...(method === "basic"
        ? {
            Authorization:
              "Basic " + Buffer.from(id + ":" + secret).toString("base64"),
          }
        : {}),
      ...headers,
    },
  );
}
async function payload(token) {
  const keys = await (await request("/jwks")).json();
  return (
    await jwtVerify(token, createLocalJWKSet(keys), { issuer, audience: id })
  ).payload;
}
async function userinfo(token) {
  return request("/userinfo", null, { Authorization: "Bearer " + token });
}

test("static client discovery and code flow support basic/post authentication and bounded claims", async (t) => {
  const discovery = await (
    await request("/.well-known/openid-configuration")
  ).json();
  assert.equal(discovery.require_signed_request_object, false);
  assert.ok(
    discovery.token_endpoint_auth_methods_supported.includes(
      "client_secret_basic",
    ),
  );
  assert.ok(
    discovery.token_endpoint_auth_methods_supported.includes(
      "client_secret_post",
    ),
  );
  for (const method of ["basic", "post"])
    await t.test(method, async () => {
      const g = await grant(
        { scope: "openid profile email" },
        method === "post",
      );
      const r = await redeem(g.code, method);
      assert.equal(r.status, 200, await r.clone().text());
      const tokens = await r.json();
      const claims = await payload(tokens.id_token);
      assert.equal(claims.nonce, "nonce-preserved");
      assert.equal(claims.acr, "urn:teraland:acr:password");
      assert.deepEqual(claims.amr, ["pwd"]);
      assert.ok(claims.auth_time <= claims.iat);
      assert.equal(claims.email, undefined);
      const profile = await (await userinfo(tokens.access_token)).json();
      assert.equal(profile.sub, claims.sub);
      assert.equal(profile.name, "Alice");
      assert.equal(profile.email, "alice@example.test");
      const body = await request("/userinfo", {
        access_token: tokens.access_token,
      });
      assert.equal(body.status, 200);
      assert.deepEqual(await body.json(), profile);
      assert.equal(
        (
          await request(
            "/userinfo",
            { access_token: tokens.access_token },
            { Authorization: "Bearer " + tokens.access_token },
          )
        ).status,
        400,
      );
    });
  for (const extra of [
    {},
    { claims: JSON.stringify({ userinfo: { name: { essential: true } } }) },
  ]) {
    const g = await grant(extra);
    const tokens = await (await redeem(g.code)).json();
    const profile = await (await userinfo(tokens.access_token)).json();
    assert.equal(profile.email, undefined);
    assert.equal(profile.name, extra.claims ? "Alice" : undefined);
  }
});
test("client authentication rejects ambiguous methods and does not consume another client's code", async () => {
  const { code } = await grant();
  for (const [method, extra, headers] of [
    ["post", { client_secret: "wrong" }, {}],
    ["basic", { client_secret: secret }, {}],
    ["basic", { client_id: "other-app" }, {}],
    ["basic", { client_assertion: "unsigned" }, {}],
    ["basic", {}, { Authorization: "Basic not-valid!" }],
    [
      "basic",
      {},
      {
        Authorization: "Basic " + Buffer.from("%zz:secret").toString("base64"),
      },
    ],
  ])
    assert.equal((await redeem(code, method, extra, headers)).status, 401);
  const wrong = await redeem(code, "post", { client_id: "other-app" });
  assert.equal(wrong.status, 400);
  const tokens = await (await redeem(code)).json();
  assert.ok(tokens.access_token);
  assert.equal(
    (await redeem(code, "post", { client_id: "other-app" })).status,
    400,
  );
  assert.equal((await userinfo(tokens.access_token)).status, 200);
  assert.equal((await redeem(code)).status, 400);
  assert.equal((await userinfo(tokens.access_token)).status, 401);
  assert.equal(
    (
      await request("/token?client_secret=never-accept-query", {
        grant_type: "authorization_code",
      })
    ).status,
    400,
  );
});
test("parallel code redemption is transactional and replay revokes the issued token", async () => {
  const { code } = await grant();
  const responses = await Promise.all([redeem(code), redeem(code)]);
  assert.deepEqual(responses.map((r) => r.status).sort(), [200, 400]);
  const tokens = await responses.find((r) => r.status === 200).json();
  assert.equal((await userinfo(tokens.access_token)).status, 401);
});
test("sessions support prompt none, forced login, max_age, hints and runtime restart", async () => {
  const missing = await authorize({ prompt: "none" });
  assert.equal(
    new URL(missing.headers.get("location")).searchParams.get("error"),
    "login_required",
  );
  const g = await grant();
  const tokens = await (await redeem(g.code)).json();
  const first = await payload(tokens.id_token);
  const silent = await authorize(
    { prompt: "none", id_token_hint: tokens.id_token },
    g.cookie,
  );
  const second = await payload(
    (await (await redeem(codeFrom(silent))).json()).id_token,
  );
  assert.equal(first.auth_time, second.auth_time);
  assert.equal(first.sub, second.sub);
  const noSession = await authorize({
    prompt: "none",
    id_token_hint: tokens.id_token,
  });
  assert.equal(
    new URL(noSession.headers.get("location")).searchParams.get("error"),
    "login_required",
  );
  for (const extra of [{ prompt: "login" }, { max_age: "0" }])
    assert.equal((await authorize(extra, g.cookie)).status, 200);
  const badPrompt = await authorize({ prompt: "none login" }, g.cookie);
  assert.equal(
    new URL(badPrompt.headers.get("location")).searchParams.get("error"),
    "invalid_request",
  );
  const badHint = await authorize({ id_token_hint: "forged" }, g.cookie);
  assert.equal(
    new URL(badHint.headers.get("location")).searchParams.get("error"),
    "invalid_request",
  );
  await mf.dispose();
  mf = new Miniflare(options());
  await mf.ready;
  assert.equal(
    (await authorize({ prompt: "none", max_age: "10000" }, g.cookie)).status,
    303,
  );
  const state = await mf.getDurableObjectNamespace("STATE");
  const stub = state.get(state.idFromName(issuer));
  const sid = g.cookie.split("=")[1];
  const hash = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(sid)),
  ).toString("base64url");
  await stub.fetch("https://state.internal", {
    method: "POST",
    body: JSON.stringify({
      op: "put",
      key: "session:" + hash,
      value: {
        subject: first.sub,
        authTime: first.auth_time - 100,
        exp: Math.floor(Date.now() / 1000) + 1000,
      },
    }),
  });
  assert.equal((await authorize({ max_age: "1" }, g.cookie)).status, 200);
});
test("invalid redirects never receive callbacks; protocol errors use only the registered callback", async () => {
  for (const uri of [
    "https://attacker.example/callback",
    redirect + "&added=1",
    "",
    "https://app.example/callback",
  ]) {
    const r = await authorize({ redirect_uri: uri });
    assert.equal(r.status, 400);
    assert.equal(r.headers.has("location"), false);
    assert.equal(r.headers.has("set-cookie"), false);
  }
  for (const [extra, error] of [
    [{ response_type: "" }, "unsupported_response_type"],
    [{ scope: "openid toString" }, "invalid_scope"],
    [{ request: "not-a-jwt" }, "request_not_supported"],
    [
      { request_uri: "https://attacker.example/evil" },
      "request_uri_not_supported",
    ],
    [{ claims: "not-json" }, "invalid_request"],
    [{ claims: JSON.stringify({ userinfo: [] }) }, "invalid_request"],
    [
      { claims: JSON.stringify({ userinfo: { name: { essential: "yes" } } }) },
      "invalid_request",
    ],
    [{ max_age: "-1" }, "invalid_request"],
    [
      { code_challenge: "plain", code_challenge_method: "plain" },
      "invalid_request",
    ],
  ]) {
    const r = await authorize(extra);
    assert.equal(r.status, 303);
    const u = new URL(r.headers.get("location"));
    assert.equal(u.origin, "https://app.example");
    assert.equal(u.searchParams.get("error"), error);
    assert.equal(u.searchParams.has("code"), false);
  }
});
test("PKCE is bound to the code and credentials never appear in discovery", async () => {
  const verifier = "v".repeat(43);
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  ).toString("base64url");
  const { code } = await grant({
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  assert.equal(
    (await redeem(code, "basic", { code_verifier: "w".repeat(43) })).status,
    400,
  );
  assert.equal(
    (await redeem(code, "basic", { code_verifier: verifier })).status,
    200,
  );
  const discovery = await (
    await request("/.well-known/openid-configuration")
  ).text();
  assert.equal(discovery.includes(secret), false);
});

test("password authentication cannot satisfy an essential stronger ACR", async () => {
  const response = await authorize({
    claims: JSON.stringify({
      id_token: { acr: { essential: true, values: ["urn:example:mfa"] } },
    }),
  });
  assert.equal(response.status, 303);
  assert.equal(
    new URL(response.headers.get("location")).searchParams.get("error"),
    "access_denied",
  );
  const g = await grant({ acr_values: "urn:example:mfa" });
  const token = await (await redeem(g.code)).json();
  assert.equal(
    (await payload(token.id_token)).acr,
    "urn:teraland:acr:password",
  );
});

test("invalid static client configuration fails closed without publishing credentials", async () => {
  const client = {
    client_id: id,
    client_secret: secret,
    redirect_uris: [redirect],
  };
  for (const clients of [
    [{ ...client, client_id: "https://rp.example" }],
    [client, client],
    [{ ...client, redirect_uris: ["http://app.example/callback"] }],
    [{ ...client, token_endpoint_auth_method: "none" }],
    [{ ...client, client_secret: "short" }],
  ]) {
    const runtime = new Miniflare(
      options({ STATIC_CLIENTS: JSON.stringify(clients) }),
    );
    try {
      const response = await runtime.dispatchFetch(
        issuer + "/.well-known/openid-configuration",
      );
      assert.equal(response.status, 503);
      assert.deepEqual(await response.json(), { error: "server_error" });
    } finally {
      await runtime.dispose();
    }
  }
});
