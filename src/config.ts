import { identifier } from "./federation/discovery";
import { staticClients } from "./oidc/clients";
import { userClaims } from "./oidc/claims";
import { obj, requireThat, type Env, type Config } from "./shared/types";
import { keySet, publicKey } from "./shared/crypto";
export function configuration(env: Env): Config {
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
