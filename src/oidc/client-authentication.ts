import { verify, keySet } from "../shared/crypto";
import {
  validTimes,
  str,
  num,
  now,
  has,
  requireThat,
  type Config,
  type ObjectMap,
} from "../shared/types";
import type { Store } from "../storage/state";
export async function authenticate(
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
