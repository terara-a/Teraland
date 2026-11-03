import { form, fail, json } from "../shared/http";
import { hash, unverified } from "../shared/crypto";
import {
  str,
  now,
  random,
  type Config,
  type AuthRequest,
} from "../shared/types";
import type { Store } from "../storage/state";
import type { FederatedClients } from "./clients";
import { authenticate } from "./client-authentication";
export async function par(
  c: Config,
  store: Store,
  clients: FederatedClients,
  r: Request,
) {
  const f = await form(r);
  if (f.has("request_uri")) return fail("invalid_request");
  let a: AuthRequest;
  try {
    a = await clients.request(
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
    await authenticate(c, f, a.client, "/par", store);
  } catch {
    return fail("invalid_client", 401);
  }
  a.exp = Math.min(a.exp, now() + 90);
  if (a.exp <= now()) return fail("invalid_request_object");
  const uri = "urn:ietf:params:oauth:request_uri:" + random();
  await store.call("put", "par:" + (await hash(uri)), a);
  return json({ request_uri: uri, expires_in: a.exp - now() }, 201);
}
