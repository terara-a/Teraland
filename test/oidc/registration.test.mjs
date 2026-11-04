import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { jwtVerify, createLocalJWKSet } from "jose";
import { privateJWK } from "../../scripts/setup-local.mjs";
const issuer = "https://op.example",
  redirect = "https://app.example/callback?registered=1",
  initial = "registration-test-initial-token-".repeat(2);
let mf, dir, bindings, publicJwk;
let outbound = 0;
const options = (override = {}) => ({
  ...convertV4MiniflareOptions({
    name: "registration-tests",
    scriptPath: ".build/index.js",
    modules: true,
    compatibilityDate: "2026-10-01",
    durableObjects: { STATE: { className: "ProviderState", useSQLite: true } },
    bindings: Object.fromEntries(
      Object.entries({ ...bindings, ...override }).filter(
        ([, value]) => value !== undefined,
      ),
    ),
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
  const { d, p, q, dp, dq, qi, oth, ...pub } = signing;
  publicJwk = pub;
  dir = await mkdtemp(join(tmpdir(), "teraland-registration-"));
  bindings = {
    ISSUER: issuer,
    SIGNING_JWK: JSON.stringify(signing),
    ENCRYPTION_JWK: JSON.stringify(encryption),
    TERALAND_USERNAME: "alice",
    TERALAND_PASSWORD: "registration-test-password",
    FEDERATION_HOSTS: "[]",
    TRUST_ANCHORS: "{}",
    DYNAMIC_REGISTRATION_TOKEN: initial,
    USER_CLAIMS: JSON.stringify({ name: "Alice" }),
  };
  mf = new Miniflare(options());
  await mf.ready;
});
after(async () => {
  await mf?.dispose();
  await rm(dir, { recursive: true, force: true });
  assert.equal(outbound, 0);
});
const fetch = (path, init = {}) =>
  mf.dispatchFetch(issuer + path, { redirect: "manual", ...init });
const register = (metadata = {}, token = initial) =>
  fetch("/register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + token,
    },
    body: JSON.stringify({ redirect_uris: [redirect], ...metadata }),
  });
const form = (path, body, headers = {}) =>
  fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: new URLSearchParams(body).toString(),
  });
async function authorize(client) {
  const r = await fetch(
    "/authorize?" +
      new URLSearchParams({
        client_id: client.client_id,
        redirect_uri: redirect,
        response_type: "code",
        scope: "openid profile",
        state: "state",
        nonce: "nonce",
      }),
  );
  assert.equal(r.status, 200);
  const html = await r.text();
  const response = await form(
    "/login",
    {
      request_id: /name="request_id" value="([^"]+)"/.exec(html)[1],
      username: "alice",
      password: bindings.TERALAND_PASSWORD,
    },
    { cookie: r.headers.getSetCookie()[0].split(";")[0], origin: issuer },
  );
  assert.equal(response.status, 303);
  return new URL(response.headers.get("location")).searchParams.get("code");
}
async function redeem(
  client,
  code,
  basic = true,
  secret = client.client_secret,
) {
  return form(
    "/token",
    {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirect,
      ...(basic ? {} : { client_id: client.client_id, client_secret: secret }),
    },
    basic
      ? { Authorization: "Basic " + btoa(client.client_id + ":" + secret) }
      : {},
  );
}
test("registration requires the initial bearer token and does not leak it", async () => {
  const discovery = await (
    await fetch("/.well-known/openid-configuration")
  ).json();
  assert.equal(discovery.registration_endpoint, issuer + "/register");
  assert.equal(discovery.require_signed_request_object, false);
  for (const token of ["", "wrong-token"]) {
    const r = await register({}, token);
    assert.equal(r.status, 401);
    assert.equal(r.headers.get("cache-control"), "no-store");
    assert.match(r.headers.get("www-authenticate"), /^Bearer/);
    assert.deepEqual(await r.json(), { error: "invalid_token" });
  }
  const missing = await fetch("/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  assert.equal(missing.status, 401);
});
test("registered clients persist and complete basic/post flows with their registered authentication method", async () => {
  for (const method of ["client_secret_basic", "client_secret_post"]) {
    const r = await register({
      token_endpoint_auth_method: method,
      client_name: "Test client",
      jwks: { keys: [publicJwk] },
      unknown_extension: "ignored",
    });
    assert.equal(r.status, 201);
    assert.equal(r.headers.get("cache-control"), "no-store");
    const c = await r.json();
    assert.match(c.client_id, /^dcr_/);
    assert.ok(c.client_secret.length >= 32);
    assert.equal(c.client_secret_expires_at - c.client_id_issued_at, 86400);
    assert.equal(c.unknown_extension, undefined);
    assert.equal(c.dynamic_client, undefined);
    assert.equal(c.client_secret_hash, undefined);
    const b = await mf.getBindings();
    const stub = b.STATE.get(b.STATE.idFromName(issuer));
    const key = "client:" + (await digest(c.client_id));
    const stored = await (
      await stub.fetch("https://state.internal/", {
        method: "POST",
        body: JSON.stringify({ op: "get", key }),
      })
    ).json();
    assert.equal(stored.client_secret, undefined);
    assert.notEqual(stored.client_secret_hash, c.client_secret);
    await mf.dispose();
    mf = new Miniflare(options());
    await mf.ready;
    const code = await authorize(c),
      basic = method === "client_secret_basic";
    assert.equal((await redeem(c, code, !basic)).status, 401);
    assert.equal((await redeem(c, code, basic, "invalid-secret")).status, 401);
    const token = await redeem(c, code, basic);
    assert.equal(token.status, 200);
    const t = await token.json();
    const jwks = await (await fetch("/jwks")).json();
    const verified = await jwtVerify(t.id_token, createLocalJWKSet(jwks), {
      issuer,
      audience: c.client_id,
    });
    assert.equal(verified.payload.nonce, "nonce");
    const user = await (
      await fetch("/userinfo", {
        headers: { Authorization: "Bearer " + t.access_token },
      })
    ).json();
    assert.equal(user.name, "Alice");
    assert.equal(user.sub, verified.payload.sub);
    assert.equal((await redeem(c, code, basic)).status, 400);
    assert.equal(
      (
        await fetch("/userinfo", {
          headers: { Authorization: "Bearer " + t.access_token },
        })
      ).status,
      401,
    );
  }
});
async function digest(value) {
  return Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
  ).toString("base64url");
}
test("invalid redirects and unsupported security metadata fail before registration without outbound fetches", async () => {
  for (const uri of [
    "http://app.example/cb",
    "https://user:password@app.example/cb",
    "https://app.example/cb#fragment",
  ]) {
    const r = await register({ redirect_uris: [uri] });
    assert.equal(r.status, 400);
    assert.deepEqual(await r.json(), { error: "invalid_redirect_uri" });
  }
  for (const value of [null, [], {}, "https://app.example/cb", [42], []]) {
    const r = await register({ redirect_uris: value });
    assert.equal(r.status, 400);
  }
  for (const metadata of [
    { token_endpoint_auth_method: "none" },
    { token_endpoint_auth_method: "private_key_jwt" },
    { response_types: ["token"] },
    { grant_types: ["implicit"] },
    { application_type: "native" },
    { subject_type: "pairwise" },
    { id_token_signed_response_alg: "none" },
    { jwks_uri: "https://untrusted.example/keys" },
    { jwks: { keys: [JSON.parse(bindings.SIGNING_JWK)] } },
    { id_token_encrypted_response_alg: "RSA-OAEP" },
    { software_statement: "ignored-by-unsafe-servers" },
  ]) {
    const r = await register(metadata);
    assert.equal(r.status, 400);
    assert.deepEqual(await r.json(), { error: "invalid_client_metadata" });
  }
  const narrowed = await (
    await register({ grant_types: ["authorization_code", "refresh_token"] })
  ).json();
  assert.deepEqual(narrowed.grant_types, ["authorization_code"]);
  const uris = await register({
    request_uris: ["https://untrusted.example/request#hash"],
  });
  assert.equal(uris.status, 201);
  assert.equal(outbound, 0);
  for (const body of [
    "null",
    "[]",
    "{",
    JSON.stringify({ redirect_uris: [redirect], huge: "x".repeat(17000) }),
  ]) {
    const r = await fetch("/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + initial,
      },
      body,
    });
    assert.equal(r.status, 400);
  }
});
test("disabled registration neither advertises nor accepts clients; malformed token fails closed", async () => {
  await mf.dispose();
  mf = new Miniflare(options({ DYNAMIC_REGISTRATION_TOKEN: undefined }));
  await mf.ready;
  assert.equal(
    (await (await fetch("/.well-known/openid-configuration")).json())
      .registration_endpoint,
    undefined,
  );
  assert.equal((await register()).status, 404);
  await mf.dispose();
  mf = new Miniflare(options({ DYNAMIC_REGISTRATION_TOKEN: "short" }));
  await mf.ready;
  const r = await fetch("/healthz");
  assert.equal(r.status, 503);
  assert.deepEqual(await r.json(), { error: "server_error" });
  await mf.dispose();
  mf = new Miniflare(options());
  await mf.ready;
});
test("another dynamic client cannot redeem a code or revoke the owner's token", async () => {
  const owner = await (await register()).json(),
    other = await (await register()).json();
  const code = await authorize(owner);
  assert.equal((await redeem(other, code)).status, 400);
  const response = await redeem(owner, code);
  assert.equal(response.status, 200);
  const token = (await response.json()).access_token;
  assert.equal((await redeem(other, code)).status, 400);
  assert.equal(
    (
      await fetch("/userinfo", {
        headers: { Authorization: "Bearer " + token },
      })
    ).status,
    200,
  );
});
test("expiration prevents authentication and issuance for an expired client", async () => {
  const c = await (await register()).json(),
    code = await authorize(c);
  const b = await mf.getBindings(),
    stub = b.STATE.get(b.STATE.idFromName(issuer)),
    key = "client:" + (await digest(c.client_id));
  const stored = await (
    await stub.fetch("https://state.internal/", {
      method: "POST",
      body: JSON.stringify({ op: "get", key }),
    })
  ).json();
  await stub.fetch("https://state.internal/", {
    method: "POST",
    body: JSON.stringify({
      op: "put",
      key,
      value: { ...stored, exp: Math.floor(Date.now() / 1000) + 5 },
    }),
  });
  await new Promise((resolve) => setTimeout(resolve, 5500));
  assert.equal((await redeem(c, code)).status, 401);
  const r = await fetch(
    "/authorize?" +
      new URLSearchParams({
        client_id: c.client_id,
        redirect_uri: redirect,
        response_type: "code",
        scope: "openid",
      }),
  );
  assert.equal(r.status, 400);
  assert.equal(r.headers.has("location"), false);
  assert.equal(outbound, 0);
});
test("parallel registrations enforce the persistent client limit transactionally", async () => {
  // Use a separate issuer's DO for a fresh bounded registry.
  const isolated = "https://limit.example";
  await mf.dispose();
  mf = new Miniflare(options({ ISSUER: isolated }));
  await mf.ready;
  const binding = await mf.getBindings(),
    state = binding.STATE.get(binding.STATE.idFromName(isolated));
  for (let i = 0; i < 255; i++)
    await state.fetch("https://state.internal/", {
      method: "POST",
      body: JSON.stringify({
        op: "put",
        key: "client:fixture-" + i,
        value: { exp: Math.floor(Date.now() / 1000) + 3600 },
      }),
    });
  const create = () =>
    mf.dispatchFetch(isolated + "/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + initial,
      },
      body: JSON.stringify({ redirect_uris: [redirect] }),
    });
  const responses = await Promise.all([create(), create()]);
  assert.deepEqual(responses.map((x) => x.status).sort(), [201, 503]);
});
