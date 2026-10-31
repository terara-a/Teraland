import { form, fail, json } from "../shared/http";
import { hash, equal, sign } from "../shared/crypto";
import {
  now,
  random,
  requireThat,
  type Config,
  type Grant,
} from "../shared/types";
import type { Store } from "../storage/state";
import { base64url } from "jose";
import {
  basicCredentials,
  authenticateStatic,
  type FederatedClients,
} from "./clients";
import { authenticate } from "./client-authentication";
export async function token(
  c: Config,
  store: Store,
  clients: FederatedClients,
  r: Request,
) {
  if (new URL(r.url).search) return fail("invalid_request");
  const f = await form(r);
  if (f.get("grant_type") !== "authorization_code")
    return fail("unsupported_grant_type");
  let id = "";
  try {
    const credentials = basicCredentials(r, f);
    id = credentials.id;
    const client = c.clients[id];
    if (client) await authenticateStatic(client, credentials.secret, f);
    else {
      requireThat(
        !r.headers.has("authorization") && !f.has("client_secret"),
        "Unsupported authentication",
      );
      const rp = await clients.relyingParty(id);
      await authenticate(c, f, rp, "/token", store);
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
  const g = await store.call<Grant | null>("get", codeKey);
  if (!g) {
    await store.call("reuse", codeKey, undefined, { client: id });
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
    iss: c.issuer,
    sub: g.subject,
    aud: [id],
    iat: now(),
    exp: now() + 300,
    auth_time: g.authTime,
    at_hash: base64url.encode(digest.slice(0, 16)),
    ...g.idClaims,
    ...(g.nonce ? { nonce: g.nonce } : {}),
  };
  const jwt = await sign(c.signing, "JWT", claims);
  const consumed = await store.call(
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
