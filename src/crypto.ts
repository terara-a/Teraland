import {
  CompactSign,
  compactVerify,
  compactDecrypt,
  decodeProtectedHeader,
  decodeJwt,
  importJWK,
  base64url,
  type JWK,
} from "jose";
import { obj, requireThat, type ObjectMap, type JWKS } from "./types";
export const algorithms = ["RS256", "PS256", "ES256"];
export function keySet(value: unknown): JWKS {
  const keys = obj(value).keys;
  requireThat(
    Array.isArray(keys) && keys.length > 0 && keys.length <= 32,
    "missing public keys",
  );
  for (const k of keys) {
    requireThat(
      k &&
        typeof k === "object" &&
        !["d", "p", "q", "dp", "dq", "qi", "oth", "k"].some((n) => n in k),
      "private keys not permitted",
    );
    requireThat(
      (k.kty === "RSA" &&
        typeof k.n === "string" &&
        typeof k.e === "string" &&
        base64url.decode(k.n).length >= 256) ||
        (k.kty === "EC" &&
          k.crv === "P-256" &&
          typeof k.x === "string" &&
          typeof k.y === "string"),
      "invalid public key",
    );
  }
  return { keys: keys as JWK[] };
}
export function publicKey(k: JWK): JWK {
  const { d, p, q, dp, dq, qi, oth, k: secret, ...pub } = k;
  return pub;
}
export async function sign(key: JWK, typ: string, claims: ObjectMap) {
  return new CompactSign(new TextEncoder().encode(JSON.stringify(claims)))
    .setProtectedHeader({ alg: "RS256", kid: key.kid, typ })
    .sign(await importJWK(key, "RS256"));
}
export async function verify(
  raw: string,
  ks: JWKS,
  typ?: string,
  registered?: string,
): Promise<ObjectMap> {
  const h = decodeProtectedHeader(raw);
  requireThat(
    algorithms.includes(h.alg ?? "") &&
      (!typ || h.typ === typ) &&
      (!registered || h.alg === registered),
    "JWT header or registered algorithm mismatch",
  );
  for (const key of ks.keys) {
    if (
      (h.kid && h.kid !== key.kid) ||
      (key.use && key.use !== "sig") ||
      (key.alg && key.alg !== h.alg)
    )
      continue;
    try {
      const result = await compactVerify(raw, await importJWK(key, h.alg), {
        algorithms,
      });
      return obj(JSON.parse(new TextDecoder().decode(result.payload)));
    } catch {
      continue;
    }
  }
  throw new Error("invalid signature");
}
export function unverified(raw: string): ObjectMap {
  return obj(decodeJwt(raw));
}
export async function decrypt(raw: string, key: JWK) {
  if (raw.split(".").length !== 5) return raw;
  const h = decodeProtectedHeader(raw);
  requireThat(
    h.cty === "JWT" && ["RSA-OAEP", "RSA-OAEP-256"].includes(h.alg ?? ""),
    "invalid nested JWT",
  );
  const result = await compactDecrypt(raw, await importJWK(key, h.alg), {
    keyManagementAlgorithms: ["RSA-OAEP", "RSA-OAEP-256"],
    contentEncryptionAlgorithms: ["A256GCM"],
  });
  return new TextDecoder().decode(result.plaintext);
}
export async function hash(s: string) {
  return base64url.encode(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)),
    ),
  );
}
export async function equal(a: string, b: string) {
  const x = await hash(a),
    y = await hash(b);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}
