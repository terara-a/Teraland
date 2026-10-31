import { sign, publicKey } from "../shared/crypto";
import { now, requireThat, type Config } from "../shared/types";
import { metadata } from "../oidc/discovery";
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
export async function entityConfiguration(c: Config) {
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
}
