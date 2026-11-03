import { algorithms, keySet } from "../shared/crypto";
import {
  str,
  obj,
  strings,
  has,
  requireThat,
  type ObjectMap,
} from "../shared/types";
import type { TrustChain } from "./trust-chain";
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
export function restrictions(m: ObjectMap) {
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

export async function relyingParty(chain: TrustChain, id: string) {
  const entity = await chain.resolve(id);
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
  if (!rp.jwks) rp.jwks = JSON.parse(await chain.fetch(str(rp, "jwks_uri")));
  rp.jwks = keySet(rp.jwks);
  rp.client_id = id;
  rp.trust_exp = entity.exp;
  return rp;
}
