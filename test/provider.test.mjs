import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import {
  SignJWT,
  importJWK,
  jwtVerify,
  createLocalJWKSet,
  CompactEncrypt,
} from "jose";
import { privateJWK } from "../scripts/setup-local.mjs";
const issuer = "https://op.example",
  rp = "https://rp.example",
  anchor = "https://anchor.example";
const now = () => Math.floor(Date.now() / 1000);
const pub = (k) => {
  const { d, p, q, dp, dq, qi, oth, ...v } = k;
  return v;
};
const jwks = (k) => ({ keys: [pub(k)] });
let mf, bindings, dir, signing, encryption, rpKey, entityKey, anchorKey;
let overrides = {},
  badChain = false,
  trustExpiry = 0,
  seen = [];
async function signed(k, claims, typ = "JWT", alg = "RS256", headers = {}) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg, kid: k.kid, typ, ...headers })
    .sign(await importJWK({ ...k, alg }, alg));
}
const claims = () => ({
  iss: rp,
  client_id: rp,
  aud: issuer,
  jti: crypto.randomUUID(),
  exp: now() + 300,
  response_type: "code",
  scope: "openid",
  redirect_uri: rp + "/callback",
  nonce: "nonce",
  state: "state",
});
async function outbound(req) {
  const u = new URL(req.url);
  seen.push(u.href);
  let body, key;
  if (u.href === rp + "/.well-known/openid-federation") {
    key = entityKey;
    body = {
      iss: rp,
      sub: rp,
      jwks: jwks(entityKey),
      authority_hints: [anchor],
      metadata: {
        openid_relying_party: {
          client_registration_types: ["automatic"],
          redirect_uris: [rp + "/callback"],
          jwks_uri: rp + "/jwks",
          ...overrides,
        },
      },
    };
  } else if (u.href === anchor + "/.well-known/openid-federation") {
    key = anchorKey;
    body = {
      iss: anchor,
      sub: anchor,
      jwks: jwks(anchorKey),
      metadata: {
        federation_entity: { federation_fetch_endpoint: anchor + "/fetch" },
      },
    };
  } else if (
    u.origin === anchor &&
    u.pathname === "/fetch" &&
    u.searchParams.get("sub") === rp
  ) {
    key = badChain ? entityKey : anchorKey;
    body = { iss: anchor, sub: rp, jwks: jwks(entityKey) };
  } else if (u.href === rp + "/jwks") return Response.json(jwks(rpKey));
  else return new Response("not found", { status: 404 });
  return new Response(
    await signed(
      key,
      { iat: now(), exp: trustExpiry || now() + 3600, ...body },
      "entity-statement+jwt",
    ),
  );
}
function options() {
  return {
    ...convertV4MiniflareOptions({
      name: "teraland",
      scriptPath: ".build/index.js",
      modules: true,
      compatibilityDate: "2026-10-01",
      durableObjects: {
        STATE: { className: "ProviderState", useSQLite: true },
      },
      durableObjectsPersist: dir,
      bindings,
      outboundService: outbound,
    }),
    resourcePersistencePath: dir,
  };
}
async function request(path, params, headers = {}) {
  return mf.dispatchFetch(
    issuer + path,
    params
      ? {
          redirect: "manual",
          method: "POST",
          body: new URLSearchParams(params).toString(),
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            ...headers,
          },
        }
      : { headers, redirect: "manual" },
  );
}
async function assertion(endpoint = "/token", alg = "RS256") {
  return signed(
    rpKey,
    {
      iss: rp,
      sub: rp,
      aud: issuer + endpoint,
      exp: now() + 60,
      jti: crypto.randomUUID(),
    },
    "JWT",
    alg,
  );
}
async function authParams(endpoint, extra = {}) {
  return {
    client_id: rp,
    client_assertion_type:
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: await assertion(endpoint),
    ...extra,
  };
}
async function loginPage(raw, method = "GET") {
  const p = {
    client_id: rp,
    request: raw,
    scope: "openid",
    response_type: "code",
  };
  const r =
    method === "GET"
      ? await request("/authorize?" + new URLSearchParams(p))
      : await request("/authorize", p);
  assert.equal(r.status, 200, await r.clone().text());
  const html = await r.text();
  const id = /name="request_id" value="([^"]+)"/.exec(html)?.[1];
  assert.ok(id);
  assert.ok(r.headers.get("content-security-policy").includes(rp));
  return { id, cookie: r.headers.get("set-cookie").split(";")[0] };
}
async function login(page, password = "local-test-password") {
  return request(
    "/login",
    { request_id: page.id, username: "alice", password },
    { cookie: page.cookie, origin: issuer },
  );
}
async function codeFrom(raw, method) {
  const page = await loginPage(raw, method);
  const r = await login(page);
  assert.equal(r.status, 303, await r.clone().text());
  const u = new URL(r.headers.get("location"));
  assert.equal(u.searchParams.get("state"), "state");
  assert.equal(u.searchParams.get("iss"), issuer);
  return u.searchParams.get("code");
}
async function redeem(code, extra = {}) {
  return request(
    "/token",
    await authParams("/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: rp + "/callback",
      ...extra,
    }),
  );
}
before(async () => {
  [signing, encryption, rpKey, entityKey, anchorKey] = await Promise.all([
    privateJWK("RS256", "sig"),
    privateJWK("RSA-OAEP-256", "enc"),
    privateJWK("RS256", "sig"),
    privateJWK("RS256", "sig"),
    privateJWK("RS256", "sig"),
  ]);
  delete rpKey.alg;
  bindings = {
    ISSUER: issuer,
    SIGNING_JWK: JSON.stringify(signing),
    ENCRYPTION_JWK: JSON.stringify(encryption),
    TERALAND_USERNAME: "alice",
    TERALAND_PASSWORD: "local-test-password",
    FEDERATION_HOSTS: JSON.stringify(["rp.example", "anchor.example"]),
    TRUST_ANCHORS: JSON.stringify({ [anchor]: jwks(anchorKey) }),
  };
  dir = await mkdtemp(join(tmpdir(), "teraland-workers-"));
  mf = new Miniflare(options());
  await mf.ready;
});
after(async () => {
  await mf?.dispose();
  await rm(dir, { recursive: true, force: true });
});

test("signed discovery, public keys and health", async () => {
  assert.equal((await (await request("/healthz")).json()).status, "ok");
  const d = await (await request("/.well-known/openid-configuration")).json();
  assert.equal(d.issuer, issuer);
  const r = await request("/.well-known/openid-federation");
  assert.equal(
    r.headers.get("content-type"),
    "application/entity-statement+jwt",
  );
  const { payload } = await jwtVerify(
    await r.text(),
    createLocalJWKSet(jwks(signing)),
    { typ: "entity-statement+jwt", issuer, subject: issuer },
  );
  assert.equal(payload.metadata.openid_provider.issuer, issuer);
  const keys = await (await request("/jwks")).json();
  assert.equal(keys.keys.length, 2);
  assert.ok(keys.keys.every((k) => !k.d && !k.p));
});
test("JAR GET/POST, JWE, trust_chain and PKCE complete the flow", async (t) => {
  for (const mode of ["GET", "POST", "JWE", "JWE-OAEP", "CHAIN", "PKCE"])
    await t.test(mode, async () => {
      const c = claims();
      const verifier = "x".repeat(43);
      if (mode === "PKCE") {
        c.code_challenge = Buffer.from(
          await crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode(verifier),
          ),
        ).toString("base64url");
        c.code_challenge_method = "S256";
      }
      let raw = await signed(
        rpKey,
        c,
        "JWT",
        "RS256",
        mode === "CHAIN"
          ? { trust_chain: ["untrusted header is not used as a trust anchor"] }
          : {},
      );
      if (mode.startsWith("JWE"))
        raw = await new CompactEncrypt(new TextEncoder().encode(raw))
          .setProtectedHeader({
            alg: mode === "JWE" ? "RSA-OAEP-256" : "RSA-OAEP",
            enc: "A256GCM",
            cty: "JWT",
          })
          .encrypt(
            await importJWK(
              pub(encryption),
              mode === "JWE" ? "RSA-OAEP-256" : "RSA-OAEP",
            ),
          );
      const code = await codeFrom(raw, mode === "POST" ? "POST" : "GET");
      const response = await redeem(
        code,
        mode === "PKCE" ? { code_verifier: verifier } : {},
      );
      assert.equal(response.status, 200, await response.clone().text());
      const tokens = await response.json();
      const { payload } = await jwtVerify(
        tokens.id_token,
        createLocalJWKSet(jwks(signing)),
        { issuer, audience: rp },
      );
      assert.equal(payload.nonce, "nonce");
      assert.ok(payload.auth_time <= payload.iat);
      for (const method of ["GET", "POST"]) {
        const r = await mf.dispatchFetch(issuer + "/userinfo", {
          method,
          headers: { Authorization: "Bearer " + tokens.access_token },
        });
        assert.equal(r.status, 200);
        assert.equal((await r.json()).sub, payload.sub);
      }
      assert.equal((await redeem(code)).status, 400);
    });
});
test("PAR lifetime and client binding, one-time redemption", async () => {
  trustExpiry = now() + 15;
  try {
    const r = await request(
      "/par",
      await authParams("", { request: await signed(rpKey, claims()) }),
    );
    assert.equal(r.status, 201, await r.clone().text());
    const par = await r.json();
    assert.ok(par.expires_in > 0 && par.expires_in <= 15);
    assert.equal(
      (
        await request(
          "/authorize?" +
            new URLSearchParams({
              client_id: "https://attacker.example",
              request_uri: par.request_uri,
            }),
        )
      ).status,
      400,
    );
    const uri =
      "/authorize?" +
      new URLSearchParams({ client_id: rp, request_uri: par.request_uri });
    const results = await Promise.all([request(uri), request(uri)]);
    assert.deepEqual(results.map((r) => r.status).sort(), [200, 400]);
  } finally {
    trustExpiry = 0;
  }
});
test("invalid request claims, signatures, registration and chains are rejected", async (t) => {
  const changes = {
    missing_iss: (c) => delete c.iss,
    missing_aud: (c) => delete c.aud,
    missing_exp: (c) => delete c.exp,
    missing_jti: (c) => delete c.jti,
    sub: (c) => (c.sub = rp),
    expired: (c) => (c.exp = now() - 1),
    wrong_aud: (c) => (c.aud = "https://attacker.example"),
    wrong_client: (c) => (c.client_id = "https://attacker.example"),
    redirect: (c) => (c.redirect_uri = "https://attacker.example/callback"),
    plain_pkce: (c) => {
      c.code_challenge = "x";
      c.code_challenge_method = "plain";
    },
  };
  for (const [name, mutate] of Object.entries(changes))
    await t.test(name, async () => {
      const c = claims();
      mutate(c);
      const r = await request(
        "/authorize?" +
          new URLSearchParams({
            client_id: rp,
            request: await signed(rpKey, c),
          }),
      );
      assert.equal(r.status, 400);
    });
  badChain = true;
  try {
    assert.equal(
      (
        await request(
          "/authorize?" +
            new URLSearchParams({
              client_id: rp,
              request: await signed(rpKey, claims()),
            }),
        )
      ).status,
      400,
    );
  } finally {
    badChain = false;
  }
  assert.equal(
    (
      await request(
        "/authorize?" +
          new URLSearchParams({
            client_id: rp,
            request: await signed(entityKey, claims()),
          }),
      )
    ).status,
    400,
  );
  for (const metadata of [
    { id_token_signed_response_alg: "ES256" },
    { id_token_encrypted_response_alg: "RSA-OAEP-256" },
    { request_object_signing_alg: "none" },
  ]) {
    overrides = metadata;
    assert.equal(
      (
        await request(
          "/authorize?" +
            new URLSearchParams({
              client_id: rp,
              request: await signed(rpKey, claims()),
            }),
        )
      ).status,
      400,
    );
  }
  overrides = {};
});
test("registered PS256 restrictions apply even when JWK alg is absent", async () => {
  overrides = { request_object_signing_alg: "PS256" };
  try {
    assert.equal(
      (
        await request(
          "/authorize?" +
            new URLSearchParams({
              client_id: rp,
              request: await signed(rpKey, claims()),
            }),
        )
      ).status,
      400,
    );
    await loginPage(await signed(rpKey, claims(), "JWT", "PS256"));
  } finally {
    overrides = {};
  }
  overrides = { token_endpoint_auth_signing_alg: "PS256" };
  try {
    const r = await request(
      "/par",
      await authParams("/par", { request: await signed(rpKey, claims()) }),
    );
    assert.equal(r.status, 401);
    const p = await authParams("/par", {
      request: await signed(rpKey, claims()),
    });
    p.client_assertion = await assertion("/par", "PS256");
    assert.equal((await request("/par", p)).status, 201);
  } finally {
    overrides = {};
  }
});
test("parallel logins, CSRF, origin and credentials", async () => {
  const pages = await Promise.all([
    loginPage(await signed(rpKey, claims())),
    loginPage(await signed(rpKey, claims())),
  ]);
  const combined = pages.map((p) => p.cookie).join("; ");
  for (const p of pages) {
    const r = await login({ ...p, cookie: combined });
    assert.equal(r.status, 303);
  }
  const p = await loginPage(await signed(rpKey, claims()));
  assert.equal((await login({ ...p, cookie: pages[0].cookie })).status, 400);
  assert.equal(
    (
      await request(
        "/login",
        {
          request_id: p.id,
          username: "alice",
          password: "local-test-password",
        },
        { cookie: p.cookie, origin: "https://attacker.example" },
      )
    ).status,
    403,
  );
  assert.equal((await login(p, "wrong")).status, 401);
});
test("Durable Objects preserve pending grants and replay protection across runtime restart", async () => {
  const raw = await signed(rpKey, claims());
  const code = await codeFrom(raw);
  await mf.dispose();
  mf = new Miniflare(options());
  await mf.ready;
  assert.equal(
    (
      await request(
        "/authorize?" + new URLSearchParams({ client_id: rp, request: raw }),
      )
    ).status,
    400,
  );
  const replies = await Promise.all([redeem(code), redeem(code)]);
  assert.deepEqual(replies.map((r) => r.status).sort(), [200, 400]);
});
test("unapproved host, shared IP space and IPv4-mapped IPv6 never reach outbound fetch", async () => {
  for (const id of [
    "https://100.100.100.100",
    "https://[::ffff:100.100.100.100]",
    "https://127.0.0.1",
    "https://attacker.example",
  ]) {
    const count = seen.length;
    const c = claims();
    c.client_id = c.iss = id;
    const r = await request(
      "/authorize?" +
        new URLSearchParams({ client_id: id, request: await signed(rpKey, c) }),
    );
    assert.equal(r.status, 400);
    assert.equal(seen.length, count);
  }
});

test("new authorization code has an independent lifetime capped by federation trust", async (t) => {
  for (const par of [false, true])
    for (const capped of [false, true])
      await t.test(`par=${par}, trust cap=${capped}`, async () => {
        trustExpiry = capped ? now() + 20 : 0;
        try {
          const c = claims();
          c.exp = now() + 10;
          const raw = await signed(rpKey, c);
          let page;
          if (par) {
            const pushed = await request(
              "/par",
              await authParams("/par", { request: raw }),
            );
            assert.equal(pushed.status, 201);
            const { request_uri } = await pushed.json();
            const r = await request(
              "/authorize?" +
                new URLSearchParams({ client_id: rp, request_uri }),
            );
            assert.equal(r.status, 200);
            const html = await r.text();
            page = {
              id: /name="request_id" value="([^"]+)"/.exec(html)[1],
              cookie: r.headers.get("set-cookie").split(";")[0],
            };
          } else page = await loginPage(raw);
          const before = now();
          const response = await login(page);
          assert.equal(response.status, 303);
          const code = new URL(
            response.headers.get("location"),
          ).searchParams.get("code");
          const ns = await mf.getDurableObjectNamespace("STATE");
          const state = ns.get(ns.idFromName(issuer));
          const key =
            "code:" +
            Buffer.from(
              await crypto.subtle.digest(
                "SHA-256",
                new TextEncoder().encode(code),
              ),
            ).toString("base64url");
          const stored = await state.fetch("https://state.internal/", {
            method: "POST",
            body: JSON.stringify({ op: "get", key }),
          });
          const grant = await stored.json();
          if (capped) assert.equal(grant.exp, trustExpiry);
          else assert.ok(grant.exp >= before + 60 && grant.exp <= now() + 60);
          assert.ok(
            grant.exp > c.exp,
            "consumed request expiry must not truncate the new code",
          );
          assert.equal((await redeem(code)).status, 200);
        } finally {
          trustExpiry = 0;
        }
      });
});

test("PAR can identify a private_key_jwt client from sub without an outer client_id", async () => {
  const params = await authParams("", {
    request: await signed(rpKey, claims()),
  });
  delete params.client_id;
  assert.equal((await request("/par", params)).status, 201);
  const mismatch = await authParams("", {
    request: await signed(rpKey, claims()),
  });
  delete mismatch.client_id;
  mismatch.client_assertion = await signed(rpKey, {
    iss: "https://attacker.example",
    sub: rp,
    aud: issuer,
    jti: crypto.randomUUID(),
    exp: now() + 60,
  });
  assert.equal((await request("/par", mismatch)).status, 401);
  const forged = await authParams("", {
    request: await signed(rpKey, claims()),
  });
  delete forged.client_id;
  forged.client_assertion = await signed(entityKey, {
    iss: rp,
    sub: rp,
    aud: issuer,
    jti: crypto.randomUUID(),
    exp: now() + 60,
  });
  assert.equal((await request("/par", forged)).status, 401);
});
