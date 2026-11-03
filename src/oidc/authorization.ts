import { form } from "../shared/http";
import { hash, publicKey, verify } from "../shared/crypto";
import {
  obj,
  str,
  num,
  strings,
  has,
  now,
  type Config,
  type AuthRequest,
  type ObjectMap,
} from "../shared/types";
import type { Store } from "../storage/state";
import { basicRequest, type FederatedClients } from "./clients";
import { scopeClaims } from "./claims";
import { passwordAcr } from "../identity/method";
import type { Login } from "../identity/login";
import { readSession } from "../identity/session";
import { RequestObjectError } from "../shared/errors";
import { authorizationFailure, callback } from "./responses";
import { issueCode } from "./code";
export async function authorize(
  c: Config,
  store: Store,
  clients: FederatedClients,
  login: Login,
  r: Request,
) {
  const f = await form(r);
  let a: AuthRequest;
  const staticClient = c.clients[f.get("client_id") ?? ""];
  if (staticClient) return basicAuthorize(c, store, login, r, f, staticClient);
  if (f.has("request_uri")) {
    if (f.has("request")) return authorizationFailure("invalid_request");
    const id = f.get("client_id") ?? "";
    const saved = await store.call<AuthRequest | null>(
      "get",
      "par:" + (await hash(f.get("request_uri")!)),
    );
    if (!saved || saved.claims.client_id !== id)
      return authorizationFailure("invalid_request_uri");
    const consumed = await store.call<AuthRequest | null>(
      "take",
      "par:" + (await hash(f.get("request_uri")!)),
      undefined,
      { exp: saved.exp },
    );
    if (!consumed) return authorizationFailure("invalid_request_uri");
    a = consumed;
  } else {
    try {
      a = await clients.request(
        f.get("request") ?? "",
        f.get("client_id") ?? "",
      );
    } catch (error) {
      return authorizationFailure(
        error instanceof RequestObjectError ? error.reason : "invalid_request",
      );
    }
    for (const k of ["scope", "response_type"])
      if (f.has(k) && f.get(k) !== a.claims[k])
        return authorizationFailure("invalid_request");
  }
  if (strings(str(a.claims, "prompt").split(/\s+/)).includes("none"))
    return callback(c, a, { error: "login_required" });
  return login.form(a);
}
async function basicAuthorize(
  c: Config,
  store: Store,
  login: Login,
  r: Request,
  f: URLSearchParams,
  client: ObjectMap,
) {
  const a = basicRequest(client, f);
  if (!strings(client.redirect_uris).includes(f.get("redirect_uri") ?? ""))
    return authorizationFailure("invalid_redirect_uri");
  const error = (code: string) => callback(c, a, { error: code });
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
  const session = await readSession(r, store);
  const subject = await hash(c.issuer + "\0" + c.username);
  if (f.has("id_token_hint")) {
    try {
      const hint = await verify(f.get("id_token_hint")!, {
        keys: [publicKey(c.signing)],
      });
      if (
        hint.iss !== c.issuer ||
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
    return issueCode(c, store, a, subject, num(session, "authTime"));
  if (prompts.includes("none")) return error("login_required");
  return login.form(a);
}
