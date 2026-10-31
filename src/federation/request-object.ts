import { decodeProtectedHeader } from "jose";
import { keySet, verify, unverified, decrypt } from "../shared/crypto";
import {
  ReplayError,
  RequestObjectError,
  requestCheck,
} from "../shared/errors";
import {
  str,
  num,
  strings,
  has,
  now,
  type Config,
  type ObjectMap,
  type AuthRequest,
} from "../shared/types";
import type { Store } from "../storage/state";
export async function request(
  config: Config,
  store: Store,
  resolve: (id: string) => Promise<ObjectMap>,
  raw: string,
  id: string,
): Promise<AuthRequest> {
  let claims: ObjectMap;
  let h: ReturnType<typeof decodeProtectedHeader>;
  try {
    raw = await decrypt(raw, config.encryption);
    claims = unverified(raw);
    h = decodeProtectedHeader(raw);
  } catch {
    throw new RequestObjectError("malformed_request");
  }
  requestCheck(
    h.typ === undefined || h.typ === "JWT" || h.typ === "oauth-authz-req+jwt",
    "invalid_type",
  );
  requestCheck(id && claims.client_id === id, "invalid_client_id");
  requestCheck(claims.iss === id, "invalid_iss");
  let rp: ObjectMap;
  try {
    rp = await resolve(id);
  } catch {
    throw new RequestObjectError("untrusted_client");
  }
  let m: ObjectMap;
  try {
    m = await verify(
      raw,
      keySet(rp.jwks),
      undefined,
      str(rp, "request_object_signing_alg"),
    );
  } catch {
    throw new RequestObjectError("invalid_signature");
  }
  requestCheck(
    num(m, "exp") > now() && num(m, "exp") <= now() + 600,
    "invalid_exp",
  );
  requestCheck(num(m, "nbf") <= now() + 30, "invalid_nbf");
  requestCheck(!("sub" in m), "forbidden_sub");
  const aud = strings(m.aud);
  requestCheck(aud.length === 1 && aud[0] === config.issuer, "invalid_aud");
  requestCheck(
    has(rp.redirect_uris, str(m, "redirect_uri")),
    "invalid_redirect_uri",
  );
  requestCheck(m.response_type === "code", "invalid_response_type");
  const scopes = str(m, "scope").split(/\s+/);
  requestCheck(
    scopes.includes("openid") &&
      scopes.every((x) => ["openid", "profile"].includes(x)),
    "invalid_scope",
  );
  requestCheck(
    !m.response_mode || m.response_mode === "query",
    "invalid_response_mode",
  );
  if (m.code_challenge)
    requestCheck(
      m.code_challenge_method === "S256" &&
        /^[A-Za-z0-9_-]{43}$/.test(str(m, "code_challenge")),
      "invalid_pkce",
    );
  else requestCheck(!m.code_challenge_method, "invalid_pkce");
  const jti = str(m, "jti");
  requestCheck(jti && jti.length <= 256, "invalid_jti");
  const exp = Math.min(num(m, "exp"), num(rp, "trust_exp"));
  requestCheck(exp > now(), "expired_trust");
  try {
    await store.remember("request", id, jti, num(m, "exp"));
  } catch (error) {
    if (error instanceof ReplayError)
      throw new RequestObjectError("replayed_jti");
    throw error;
  }
  return { claims: m, client: rp, exp };
}
