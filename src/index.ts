import { limitedText } from "./http";
import {
  passwordAcr,
  staticClients,
  userClaims,
  scopeClaims,
  selectedClaims,
  basicRequest,
  basicCredentials,
  authenticateStatic,
} from "./oidc";
import {
  RequestObjectError,
  requestErrors,
  type RequestErrorReason,
} from "./errors";
import { base64url } from "jose";
import { Federation, identifier } from "./federation";
import {
  publicKey,
  sign,
  verify,
  keySet,
  hash,
  equal,
  unverified,
} from "./crypto";
import { Store } from "./state";
import {
  obj,
  str,
  num,
  strings,
  has,
  now,
  random,
  validTimes,
  requireThat,
  type Config,
  type Env,
  type ObjectMap,
  type AuthRequest,
  type Grant,
} from "./types";
export { ProviderState } from "./state";
const policy =
  "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const json = (v: unknown, status = 200) => Response.json(v, { status });
const fail = (code: string, status = 400) => json({ error: code }, status);
const escape = (s: string) =>
  s.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
function authorizationFailure(reason: RequestErrorReason = "invalid_request") {
  // An invalid request never establishes a safe callback destination. Render
  // locally, with no cookies/forms/links and no reflection of request values.
  const code =
    reason === "invalid_request_uri"
      ? reason
      : reason === "invalid_request"
        ? reason
        : "invalid_request_object";
  const html = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Teraland — Invalid authorization request</title><h1>Authorization request rejected</h1><p>Error: <code>${code}</code></p><p id="authorization-error" data-error="${code}" data-reason="${reason}">${requestErrors[reason]}</p></html>`;
  return new Response(html, {
    status: 400,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy":
        "default-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
      "Referrer-Policy": "no-referrer",
    },
  });
}
function configuration(env: Env): Config {
  identifier(env.ISSUER, env.DEV_MODE === "true");
  const signing = obj(JSON.parse(env.SIGNING_JWK)),
    encryption = obj(JSON.parse(env.ENCRYPTION_JWK));
  for (const k of [signing, encryption]) {
    requireThat(
      k.kty === "RSA" &&
        typeof k.d === "string" &&
        typeof k.kid === "string" &&
        k.kid.length > 0,
      "RSA private JWK required",
    );
    keySet({ keys: [publicKey(k)] });
  }
  requireThat(
    signing.use === "sig" && signing.alg === "RS256",
    "invalid signing key purpose",
  );
  requireThat(
    encryption.use === "enc" &&
      (!encryption.alg ||
        ["RSA-OAEP", "RSA-OAEP-256"].includes(String(encryption.alg))),
    "invalid encryption key purpose",
  );
  requireThat(
    signing.kid !== encryption.kid && signing.n !== encryption.n,
    "separate signing and encryption keys required",
  );
  requireThat(
    env.TERALAND_USERNAME && env.TERALAND_PASSWORD?.length >= 12,
    "login configuration required",
  );
  const hosts: unknown = JSON.parse(env.FEDERATION_HOSTS),
    anchors = obj(JSON.parse(env.TRUST_ANCHORS));
  requireThat(
    Array.isArray(hosts) &&
      hosts.every(
        (h) =>
          typeof h === "string" &&
          /^[a-z0-9.-]+$/i.test(h) &&
          h === h.toLowerCase() &&
          !/^\d+(\.\d+)*$/.test(h),
      ),
    "invalid federation hosts",
  );
  for (const [id, ks] of Object.entries(anchors)) {
    identifier(id);
    keySet(ks);
  }
  return {
    issuer: env.ISSUER,
    signing,
    encryption,
    username: env.TERALAND_USERNAME,
    password: env.TERALAND_PASSWORD,
    hosts,
    anchors: anchors as Config["anchors"],
    clients: staticClients(env.STATIC_CLIENTS),
    userClaims: userClaims(env.USER_CLAIMS),
  };
}
function metadata(c: Config) {
  return {
    issuer: c.issuer,
    authorization_endpoint: c.issuer + "/authorize",
    token_endpoint: c.issuer + "/token",
    userinfo_endpoint: c.issuer + "/userinfo",
    jwks_uri: c.issuer + "/jwks",
    pushed_authorization_request_endpoint: c.issuer + "/par",
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code"],
    subject_types_supported: ["public"],
    scopes_supported: [
      "openid",
      "profile",
      ...(Object.keys(c.clients).length ? ["email", "address", "phone"] : []),
    ],
    claims_supported: [
      "iss",
      "sub",
      "aud",
      "exp",
      "iat",
      "auth_time",
      "nonce",
      ...Object.keys(c.userClaims),
      ...(Object.keys(c.clients).length ? ["acr", "amr"] : []),
    ],
    claims_parameter_supported: Object.keys(c.clients).length > 0,
    ...(Object.keys(c.clients).length
      ? { acr_values_supported: [passwordAcr] }
      : {}),
    id_token_signing_alg_values_supported: ["RS256"],
    request_object_signing_alg_values_supported: ["RS256", "PS256", "ES256"],
    token_endpoint_auth_methods_supported: [
      "private_key_jwt",
      ...(Object.keys(c.clients).length
        ? ["client_secret_basic", "client_secret_post"]
        : []),
    ],
    token_endpoint_auth_signing_alg_values_supported: [
      "RS256",
      "PS256",
      "ES256",
    ],
    request_parameter_supported: true,
    request_uri_parameter_supported: false,
    require_signed_request_object: Object.keys(c.clients).length === 0,
    client_registration_types_supported: ["automatic"],
    code_challenge_methods_supported: ["S256"],
    authorization_response_iss_parameter_supported: true,
    request_object_encryption_alg_values_supported: [
      "RSA-OAEP-256",
      "RSA-OAEP",
    ],
    request_object_encryption_enc_values_supported: ["A256GCM"],
  };
}
async function form(r: Request) {
  const p = new URL(r.url).searchParams;
  requireThat(["GET", "POST"].includes(r.method), "invalid method");
  if (r.method === "POST") {
    requireThat(
      r.headers.get("content-type")?.split(";")[0].trim() ===
        "application/x-www-form-urlencoded",
      "invalid form type",
    );
    const body = await limitedText(r.body);
    for (const [k, v] of new URLSearchParams(body)) p.append(k, v);
  }
  for (const k of p.keys())
    requireThat(p.getAll(k).length === 1, "duplicate parameter");
  return p;
}
function callback(c: Config, a: AuthRequest, values: ObjectMap) {
  const u = new URL(str(a.claims, "redirect_uri"));
  for (const [k, v] of Object.entries(values)) u.searchParams.set(k, String(v));
  u.searchParams.set("iss", c.issuer);
  if (a.claims.state) u.searchParams.set("state", str(a.claims, "state"));
  return new Response(null, { status: 303, headers: { Location: u.href } });
}
function cookie(c: Config, id: string, value: string, age = 300) {
  return `teraland_login_${id}=${value}; Path=${new URL(c.issuer).pathname.replace(/\/$/, "")}/login; HttpOnly; ${new URL(c.issuer).protocol === "https:" ? "Secure; " : ""}SameSite=Strict; Max-Age=${age}`;
}
async function authenticate(
  c: Config,
  f: URLSearchParams,
  rp: ObjectMap,
  endpoint: string,
  store: Store,
) {
  requireThat(
    f.get("client_assertion_type") ===
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "invalid assertion type",
  );
  const m = await verify(
    f.get("client_assertion") ?? "",
    keySet(rp.jwks),
    undefined,
    str(rp, "token_endpoint_auth_signing_alg"),
  );
  validTimes(m);
  const id = str(rp, "client_id");
  requireThat(
    m.iss === id &&
      m.sub === id &&
      num(m, "exp") <= now() + 600 &&
      (has(m.aud, c.issuer) ||
        has(m.aud, c.issuer + endpoint) ||
        (endpoint === "/par" && has(m.aud, c.issuer + "/token"))),
    "invalid client assertion",
  );
  await store.remember("assertion", id, str(m, "jti"), num(m, "exp"));
}
class Provider {
  private federation: Federation;
  constructor(
    private c: Config,
    private store: Store,
  ) {
    this.federation = new Federation(c, store, AbortSignal.timeout(20000));
  }
  async handle(r: Request): Promise<Response> {
    const base = new URL(this.c.issuer).pathname.replace(/\/$/, "");
    const path = new URL(r.url).pathname.slice(base.length);
    requireThat(new URL(r.url).pathname.startsWith(base + "/"), "invalid path");
    const c = this.c;
    if (path === "/healthz" && r.method === "GET")
      return json({ status: "ok" });
    if (path === "/.well-known/openid-configuration" && r.method === "GET")
      return json(metadata(c));
    if (path === "/jwks" && r.method === "GET")
      return json({ keys: [publicKey(c.signing), publicKey(c.encryption)] });
    if (path === "/.well-known/openid-federation" && r.method === "GET")
      return new Response(
        await sign(c.signing, "entity-statement+jwt", {
          iss: c.issuer,
          sub: c.issuer,
          iat: now(),
          exp: now() + 3600,
          jwks: { keys: [publicKey(c.signing)] },
          metadata: {
            openid_provider: {
              ...metadata(c),
              require_signed_request_object: true,
            },
          },
          ...(Object.keys(c.anchors).length
            ? { authority_hints: Object.keys(c.anchors) }
            : {}),
        }),
        { headers: { "Content-Type": "application/entity-statement+jwt" } },
      );
    if (path === "/userinfo" && ["GET", "POST"].includes(r.method)) {
      const authorization = r.headers.get("authorization");
      const body =
        r.method === "POST" &&
        r.headers.get("content-type")?.split(";")[0].trim() ===
          "application/x-www-form-urlencoded"
          ? new URLSearchParams(await limitedText(r.body))
          : new URLSearchParams();
      if (
        new URL(r.url).searchParams.has("access_token") ||
        (authorization && body.has("access_token")) ||
        body.getAll("access_token").length > 1
      )
        return fail("invalid_request");
      const match = authorization
        ? /^Bearer (\S+)$/i.exec(authorization)
        : null;
      const token =
        match?.[1] ?? (!authorization ? body.get("access_token") : null);
      const a = token
        ? await this.store.call<ObjectMap | null>(
            "get",
            "token:" + (await hash(token)),
          )
        : null;
      return a
        ? json({ ...obj(a.userinfo), sub: a.subject })
        : new Response(JSON.stringify({ error: "invalid_token" }), {
            status: 401,
            headers: {
              "Content-Type": "application/json",
              "WWW-Authenticate": 'Bearer error="invalid_token"',
            },
          });
    }
    if (path === "/authorize" && ["GET", "POST"].includes(r.method))
      return this.authorize(r).catch(() => authorizationFailure());
    if (path === "/par" && r.method === "POST") return this.par(r);
    if (path === "/login" && r.method === "POST") return this.login(r);
    if (path === "/token" && r.method === "POST") return this.token(r);
    return fail("not_found", 404);
  }
  async par(r: Request) {
    const f = await form(r);
    if (f.has("request_uri")) return fail("invalid_request");
    let a: AuthRequest;
    try {
      a = await this.federation.request(
        f.get("request") ?? "",
        // With private_key_jwt, sub supplies the client identity when the
        // outer client_id is absent. This is only a discovery hint: both the
        // request object and the assertion are independently verified below.
        f.get("client_id") ??
          str(unverified(f.get("client_assertion") ?? ""), "sub"),
      );
    } catch {
      return fail("invalid_request_object");
    }
    try {
      await authenticate(this.c, f, a.client, "/par", this.store);
    } catch {
      return fail("invalid_client", 401);
    }
    a.exp = Math.min(a.exp, now() + 90);
    if (a.exp <= now()) return fail("invalid_request_object");
    const uri = "urn:ietf:params:oauth:request_uri:" + random();
    await this.store.call("put", "par:" + (await hash(uri)), a);
    return json({ request_uri: uri, expires_in: a.exp - now() }, 201);
  }
  async authorize(r: Request) {
    const f = await form(r);
    let a: AuthRequest;
    const staticClient = this.c.clients[f.get("client_id") ?? ""];
    if (staticClient) return this.basicAuthorize(r, f, staticClient);
    if (f.has("request_uri")) {
      if (f.has("request")) return authorizationFailure("invalid_request");
      const id = f.get("client_id") ?? "";
      const saved = await this.store.call<AuthRequest | null>(
        "get",
        "par:" + (await hash(f.get("request_uri")!)),
      );
      if (!saved || saved.claims.client_id !== id)
        return authorizationFailure("invalid_request_uri");
      const consumed = await this.store.call<AuthRequest | null>(
        "take",
        "par:" + (await hash(f.get("request_uri")!)),
        undefined,
        { exp: saved.exp },
      );
      if (!consumed) return authorizationFailure("invalid_request_uri");
      a = consumed;
    } else {
      try {
        a = await this.federation.request(
          f.get("request") ?? "",
          f.get("client_id") ?? "",
        );
      } catch (error) {
        return authorizationFailure(
          error instanceof RequestObjectError
            ? error.reason
            : "invalid_request",
        );
      }
      for (const k of ["scope", "response_type"])
        if (f.has(k) && f.get(k) !== a.claims[k])
          return authorizationFailure("invalid_request");
    }
    if (strings(str(a.claims, "prompt").split(/\s+/)).includes("none"))
      return callback(this.c, a, { error: "login_required" });
    return this.loginForm(a);
  }
  async basicAuthorize(r: Request, f: URLSearchParams, client: ObjectMap) {
    const a = basicRequest(client, f);
    if (!strings(client.redirect_uris).includes(f.get("redirect_uri") ?? ""))
      return authorizationFailure("invalid_redirect_uri");
    const error = (code: string) => callback(this.c, a, { error: code });
    if (f.has("request")) return error("request_not_supported");
    if (f.has("request_uri")) return error("request_uri_not_supported");
    if (!f.has("response_type")) return error("invalid_request");
    if (f.get("response_type") !== "code")
      return error("unsupported_response_type");
    const scopes = (f.get("scope") ?? "").split(/\s+/);
    if (
      !scopes.includes("openid") ||
      scopes.some((s) => s !== "openid" && !Object.hasOwn(scopeClaims, s))
    )
      return error("invalid_scope");
    if (f.has("response_mode") && f.get("response_mode") !== "query")
      return error("invalid_request");
    if (f.has("code_challenge") || f.has("code_challenge_method")) {
      if (
        f.get("code_challenge_method") !== "S256" ||
        !/^[A-Za-z0-9_-]{43}$/.test(f.get("code_challenge") ?? "")
      )
        return error("invalid_request");
    }
    if (f.has("claims")) {
      try {
        const requested = JSON.parse(f.get("claims")!);
        if (
          !requested ||
          typeof requested !== "object" ||
          Array.isArray(requested)
        )
          return error("invalid_request");
        for (const part of ["userinfo", "id_token"]) {
          if (
            part in requested &&
            (!requested[part] ||
              typeof requested[part] !== "object" ||
              Array.isArray(requested[part]))
          )
            return error("invalid_request");
          for (const value of Object.values(obj(requested[part]))) {
            if (
              value !== null &&
              (typeof value !== "object" || Array.isArray(value))
            )
              return error("invalid_request");
            const claim = obj(value);
            if ("essential" in claim && typeof claim.essential !== "boolean")
              return error("invalid_request");
          }
        }
        const acr = obj(obj(requested).id_token).acr;
        const requirement = obj(acr);
        if (
          requirement.essential === true &&
          (("value" in requirement && requirement.value !== passwordAcr) ||
            ("values" in requirement &&
              !strings(requirement.values).includes(passwordAcr)))
        )
          return error("access_denied");
        a.claims.claims = requested;
      } catch {
        return error("invalid_request");
      }
    }
    const prompts = (f.get("prompt") ?? "").split(/\s+/).filter(Boolean);
    if (
      prompts.some(
        (p) => !["none", "login", "consent", "select_account"].includes(p),
      ) ||
      (prompts.includes("none") && prompts.length !== 1)
    )
      return error("invalid_request");
    let maxAge: number | undefined;
    if (f.has("max_age")) {
      if (
        !/^\d+$/.test(f.get("max_age")!) ||
        !Number.isSafeInteger(Number(f.get("max_age")))
      )
        return error("invalid_request");
      maxAge = Number(f.get("max_age"));
    }
    const sessionId = (r.headers.get("cookie") ?? "")
      .split(";")
      .map((x) => x.trim())
      .find((x) => x.startsWith("teraland_session="))
      ?.slice("teraland_session=".length);
    const session =
      sessionId && /^[a-f0-9-]{68}$/.test(sessionId)
        ? await this.store.call<ObjectMap | null>(
            "get",
            "session:" + (await hash(sessionId)),
          )
        : null;
    const subject = await hash(this.c.issuer + "\0" + this.c.username);
    if (f.has("id_token_hint")) {
      try {
        const hint = await verify(f.get("id_token_hint")!, {
          keys: [publicKey(this.c.signing)],
        });
        if (
          hint.iss !== this.c.issuer ||
          hint.sub !== subject ||
          !has(hint.aud, str(client, "client_id"))
        )
          return error("invalid_request");
      } catch {
        return error("invalid_request");
      }
    }
    if (
      session &&
      session.subject === subject &&
      !prompts.includes("login") &&
      !prompts.includes("select_account") &&
      !prompts.includes("consent") &&
      (maxAge === undefined ||
        (maxAge > 0 && now() - num(session, "authTime") <= maxAge))
    )
      return this.issueCode(a, subject, num(session, "authTime"));
    if (prompts.includes("none")) return error("login_required");
    return this.loginForm(a);
  }
  async loginForm(a: AuthRequest) {
    const id = random();
    a.csrf = random();
    await this.store.call("put", "login:" + id, a);
    const origin = new URL(str(a.claims, "redirect_uri")).origin;
    const html = `<!doctype html><html lang="ja"><meta charset="utf-8"><title>Teraland ログイン</title><h1>Teraland</h1><p>${escape(str(a.claims, "client_id"))} にログインします。</p><form method="post" action="${escape(this.c.issuer + "/login")}"><input type="hidden" name="request_id" value="${id}"><label>ユーザー名 <input name="username" autocomplete="username" required></label><label>パスワード <input name="password" type="password" autocomplete="current-password" required></label><button type="submit">ログインして許可</button></form></html>`;
    return new Response(html, {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Set-Cookie": cookie(this.c, id, a.csrf),
        // no-referrer makes Chromium send Origin: null on a form POST.
        // Retain same-origin checks without leaking the request URL to the RP.
        "Referrer-Policy": "same-origin",
        "Content-Security-Policy": policy.replace(
          "form-action 'self'",
          `form-action 'self' ${origin}`,
        ),
      },
    });
  }
  async login(r: Request) {
    const f = await form(r),
      id = f.get("request_id") ?? "";
    if (!/^[a-f0-9-]{68}$/.test(id)) return fail("invalid_request");
    const csrf = (r.headers.get("cookie") ?? "")
      .split(";")
      .map((x) => x.trim())
      .find((x) => x.startsWith("teraland_login_" + id + "="))
      ?.split("=")[1];
    if (!csrf) return fail("invalid_request");
    const origin = r.headers.get("origin");
    if (origin && origin !== new URL(this.c.issuer).origin)
      return fail("access_denied", 403);
    const a = await this.store.call<AuthRequest | null>(
      "take",
      "login:" + id,
      undefined,
      { csrf },
    );
    if (!a) return fail("invalid_request");
    let response: Response;
    if (
      !(await equal(f.get("username") ?? "", this.c.username)) ||
      !(await equal(f.get("password") ?? "", this.c.password))
    )
      response = fail("access_denied", 401);
    else {
      const subject = await hash(this.c.issuer + "\0" + this.c.username),
        authTime = now();
      response = await this.issueCode(a, subject, authTime);
      if (a.client.static_client) {
        const session = random();
        await this.store.call("put", "session:" + (await hash(session)), {
          subject,
          authTime,
          exp: now() + 3600,
        });
        response.headers.append(
          "Set-Cookie",
          `teraland_session=${session}; Path=${new URL(this.c.issuer).pathname.replace(/\/$/, "")}/; HttpOnly; ${new URL(this.c.issuer).protocol === "https:" ? "Secure; " : ""}SameSite=Lax; Max-Age=3600`,
        );
      }
    }
    response.headers.append("Set-Cookie", cookie(this.c, id, "", 0));
    return response;
  }
  async issueCode(a: AuthRequest, subject: string, authTime: number) {
    const code = random();
    const requested = obj(a.claims.claims);
    const g: Grant = {
      client: str(a.claims, "client_id"),
      redirect: str(a.claims, "redirect_uri"),
      nonce: str(a.claims, "nonce"),
      scope: str(a.claims, "scope"),
      challenge: str(a.claims, "code_challenge"),
      subject,
      authTime,
      exp: Math.min(now() + 60, num(a.client, "trust_exp")),
      ...(a.client.static_client
        ? {
            userinfo: selectedClaims(
              this.c.userClaims,
              str(a.claims, "scope"),
              requested.userinfo,
            ),
            idClaims: {
              ...selectedClaims(this.c.userClaims, "", requested.id_token),
              acr: passwordAcr,
              amr: ["pwd"],
            },
          }
        : {}),
    };
    await this.store.call("put", "code:" + (await hash(code)), g);
    return callback(this.c, a, { code });
  }
  async token(r: Request) {
    if (new URL(r.url).search) return fail("invalid_request");
    const f = await form(r);
    if (f.get("grant_type") !== "authorization_code")
      return fail("unsupported_grant_type");
    let id = "";
    try {
      const credentials = basicCredentials(r, f);
      id = credentials.id;
      const client = this.c.clients[id];
      if (client) await authenticateStatic(client, credentials.secret, f);
      else {
        requireThat(
          !r.headers.has("authorization") && !f.has("client_secret"),
          "Unsupported authentication",
        );
        const rp = await this.federation.relyingParty(id);
        await authenticate(this.c, f, rp, "/token", this.store);
      }
    } catch {
      return new Response(JSON.stringify({ error: "invalid_client" }), {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "WWW-Authenticate": 'Basic realm="Teraland"',
        },
      });
    }
    const codeKey = "code:" + (await hash(f.get("code") ?? ""));
    const g = await this.store.call<Grant | null>("get", codeKey);
    if (!g) {
      await this.store.call("reuse", codeKey, undefined, { client: id });
      return fail("invalid_grant");
    }
    if (g.client !== id || g.redirect !== f.get("redirect_uri"))
      return fail("invalid_grant");
    if (g.challenge) {
      const v = f.get("code_verifier") ?? "";
      if (
        !/^[A-Za-z0-9._~-]{43,128}$/.test(v) ||
        !(await equal(await hash(v), g.challenge))
      )
        return fail("invalid_grant");
    }
    const token = random();
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)),
    );
    const claims = {
      iss: this.c.issuer,
      sub: g.subject,
      aud: [id],
      iat: now(),
      exp: now() + 300,
      auth_time: g.authTime,
      at_hash: base64url.encode(digest.slice(0, 16)),
      ...g.idClaims,
      ...(g.nonce ? { nonce: g.nonce } : {}),
    };
    const jwt = await sign(this.c.signing, "JWT", claims);
    const consumed = await this.store.call(
      "redeem",
      codeKey,
      {
        tokenKey: "token:" + (await hash(token)),
        token: { subject: g.subject, userinfo: g.userinfo, exp: now() + 300 },
      },
      { client: id },
    );
    if (!consumed) return fail("invalid_grant");
    return json({
      access_token: token,
      token_type: "Bearer",
      expires_in: 300,
      id_token: jwt,
      scope: g.scope,
    });
  }
}
export default {
  async fetch(r: Request, env: Env): Promise<Response> {
    let response: Response;
    let c: Config;
    try {
      c = configuration(env);
    } catch {
      return new Response(JSON.stringify({ error: "server_error" }), {
        status: 503,
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
        },
      });
    }
    try {
      const store = new Store(env.STATE.get(env.STATE.idFromName(c.issuer)));
      response = await new Provider(c, store).handle(r);
    } catch {
      response = fail("invalid_request");
    }
    const headers = new Headers(response.headers);
    headers.set("Cache-Control", "no-store");
    headers.set("Pragma", "no-cache");
    headers.set("X-Content-Type-Options", "nosniff");
    if (!headers.has("Referrer-Policy"))
      headers.set("Referrer-Policy", "no-referrer");
    if (!headers.has("Content-Security-Policy"))
      headers.set("Content-Security-Policy", policy);
    return new Response(response.body, { status: response.status, headers });
  },
} satisfies ExportedHandler<Env>;
