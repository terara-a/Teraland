import { limitedText } from "./http";
import { ReplayError, RequestObjectError, requestCheck } from "./errors";
import { decodeProtectedHeader } from "jose";
import { keySet, verify, unverified, decrypt, algorithms } from "./crypto";
import {
  obj,
  str,
  num,
  strings,
  has,
  now,
  validTimes,
  requireThat,
  type ObjectMap,
  type AuthRequest,
  type Config,
} from "./types";
import type { Store } from "./state";
export function identifier(value: string, local = false): URL {
  const u = new URL(value);
  requireThat(
    (u.protocol === "https:" ||
      (local && u.protocol === "http:" && u.hostname === "localhost")) &&
      !u.username &&
      !u.password &&
      !u.hash &&
      !u.search &&
      !value.endsWith("/"),
    "invalid entity identifier",
  );
  return u;
}
export function cryptoMetadata(rp: ObjectMap) {
  for (const k of [
    "request_object_signing_alg",
    "token_endpoint_auth_signing_alg",
  ])
    if (k in rp)
      requireThat(algorithms.includes(str(rp, k)), "unsupported " + k);
  if ("id_token_signed_response_alg" in rp)
    requireThat(
      rp.id_token_signed_response_alg === "RS256",
      "only RS256 ID tokens supported",
    );
  requireThat(
    !("id_token_encrypted_response_alg" in rp) &&
      !("id_token_encrypted_response_enc" in rp),
    "encrypted ID tokens unsupported",
  );
}
function restrictions(m: ObjectMap) {
  for (const k of [
    "crit",
    "policy_language_crit",
    "constraints",
    "metadata_policy",
    "trust_mark_issuers",
    "trust_mark_owners",
  ])
    requireThat(!(k in m), "unsupported federation restriction");
}
export class Federation {
  private budget = 24;
  constructor(
    private config: Config,
    private store: Store,
    private signal: AbortSignal,
  ) {}
  async fetch(uri: string) {
    const u = new URL(uri);
    // Workers cannot pin DNS results to sockets. Only operator-approved DNS hosts
    // are eligible, never IP literals, redirects, arbitrary hosts or ports.
    requireThat(
      u.protocol === "https:" &&
        !u.username &&
        !u.password &&
        !u.hash &&
        (!u.port || u.port === "443") &&
        this.config.hosts.includes(u.hostname) &&
        /^[a-z0-9.-]+$/i.test(u.hostname) &&
        !/^\d+(\.\d+)*$/.test(u.hostname),
      "federation destination not allowed",
    );
    requireThat(this.budget-- > 0, "federation fetch budget exceeded");
    const r = await fetch(u, {
      redirect: "manual",
      signal: this.signal,
      headers: { Accept: "application/entity-statement+jwt, application/json" },
    });
    requireThat(r.status === 200 && r.body, "federation fetch failed");
    return limitedText(r.body);
  }
  async resolve(
    id: string,
    seen = new Set<string>(),
    depth = 0,
  ): Promise<ObjectMap> {
    identifier(id);
    requireThat(depth <= 5 && !seen.has(id), "trust chain depth or cycle");
    seen.add(id);
    try {
      const raw = await this.fetch(id + "/.well-known/openid-federation");
      const leaf = await verify(
        raw,
        keySet(unverified(raw).jwks),
        "entity-statement+jwt",
      );
      requireThat(
        leaf.iss === id && leaf.sub === id,
        "entity identifier mismatch",
      );
      validTimes(leaf, true);
      restrictions(leaf);
      if (this.config.anchors[id]) {
        await verify(raw, this.config.anchors[id], "entity-statement+jwt");
        return leaf;
      }
      const hints = strings(leaf.authority_hints);
      requireThat(hints.length <= 8, "too many authority hints");
      for (const parent of hints) {
        try {
          const superior = await this.resolve(parent, seen, depth + 1);
          const fed = obj(obj(superior.metadata).federation_entity);
          const endpoint = new URL(str(fed, "federation_fetch_endpoint"));
          endpoint.searchParams.set("sub", id);
          endpoint.searchParams.set("iss", parent);
          const statement = await verify(
            await this.fetch(endpoint.href),
            keySet(superior.jwks),
            "entity-statement+jwt",
          );
          requireThat(
            statement.iss === parent && statement.sub === id,
            "subordinate identifier mismatch",
          );
          validTimes(statement, true);
          restrictions(statement);
          await verify(raw, keySet(statement.jwks), "entity-statement+jwt");
          leaf.exp = Math.min(
            num(leaf, "exp"),
            num(superior, "exp"),
            num(statement, "exp"),
          );
          const metadata = obj(leaf.metadata);
          for (const [typ, v] of Object.entries(obj(statement.metadata)))
            metadata[typ] = { ...obj(metadata[typ]), ...obj(v) };
          leaf.metadata = metadata;
          return leaf;
        } catch {
          continue;
        }
      }
      throw new Error("no valid path to a pinned trust anchor");
    } finally {
      seen.delete(id);
    }
  }
  async relyingParty(id: string) {
    const entity = await this.resolve(id);
    const rp = obj(obj(entity.metadata).openid_relying_party);
    requireThat(
      has(rp.client_registration_types, "automatic"),
      "automatic RP registration required",
    );
    const redirects = strings(rp.redirect_uris);
    requireThat(redirects.length > 0, "missing redirect URIs");
    for (const uri of redirects) {
      const u = new URL(uri);
      requireThat(
        u.protocol === "https:" && !u.username && !u.password && !u.hash,
        "invalid redirect URI",
      );
    }
    requireThat(
      !("token_endpoint_auth_method" in rp) ||
        rp.token_endpoint_auth_method === "private_key_jwt",
      "private_key_jwt required",
    );
    cryptoMetadata(rp);
    requireThat(!(rp.jwks && rp.jwks_uri), "ambiguous RP keys");
    if (!rp.jwks) rp.jwks = JSON.parse(await this.fetch(str(rp, "jwks_uri")));
    rp.jwks = keySet(rp.jwks);
    rp.client_id = id;
    rp.trust_exp = entity.exp;
    return rp;
  }
  async request(raw: string, id: string): Promise<AuthRequest> {
    let claims: ObjectMap;
    let h: ReturnType<typeof decodeProtectedHeader>;
    try {
      raw = await decrypt(raw, this.config.encryption);
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
      rp = await this.relyingParty(id);
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
    requestCheck(
      aud.length === 1 && aud[0] === this.config.issuer,
      "invalid_aud",
    );
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
      await this.store.remember("request", id, jti, num(m, "exp"));
    } catch (error) {
      if (error instanceof ReplayError)
        throw new RequestObjectError("replayed_jti");
      throw error;
    }
    return { claims: m, client: rp, exp };
  }
}
