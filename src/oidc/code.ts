import { hash } from "../shared/crypto";
import {
  obj,
  str,
  num,
  now,
  random,
  type Config,
  type AuthRequest,
  type Grant,
} from "../shared/types";
import type { Store } from "../storage/state";
import { selectedClaims } from "./claims";
import { passwordAcr } from "../identity/method";
import { callback } from "./responses";
export async function issueCode(
  c: Config,
  store: Store,
  a: AuthRequest,
  subject: string,
  authTime: number,
) {
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
            c.userClaims,
            str(a.claims, "scope"),
            requested.userinfo,
          ),
          idClaims: {
            ...selectedClaims(c.userClaims, "", requested.id_token),
            acr: passwordAcr,
            amr: ["pwd"],
          },
        }
      : {}),
  };
  await store.call("put", "code:" + (await hash(code)), g);
  return callback(c, a, { code });
}
