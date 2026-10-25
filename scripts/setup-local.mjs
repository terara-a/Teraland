import { generateKeyPair, exportJWK } from "jose";
import { writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";

export async function privateJWK(alg, use) {
  const { privateKey } = await generateKeyPair(alg, {
    modulusLength: 2048,
    extractable: true,
  });
  return {
    ...(await exportJWK(privateKey)),
    kid: randomBytes(24).toString("base64url"),
    use,
    ...(use === "sig" ? { alg } : {}),
  };
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const vars = {
    ISSUER: "http://localhost:8787",
    DEV_MODE: "true",
    FEDERATION_HOSTS: "[]",
    TRUST_ANCHORS: "{}",
    TERALAND_USERNAME: "alice",
    TERALAND_PASSWORD: randomBytes(24).toString("base64url"),
    SIGNING_JWK: JSON.stringify(await privateJWK("RS256", "sig")),
    ENCRYPTION_JWK: JSON.stringify(await privateJWK("RSA-OAEP-256", "enc")),
  };
  const content =
    Object.entries(vars)
      .map(([k, v]) => `${k}='${v}'`)
      .join("\n") + "\n";
  await writeFile(".dev.vars", content, { flag: "wx", mode: 0o600 });
  console.log(
    "Created .dev.vars with local keys and a generated password. Existing files are never overwritten. Set ISSUER and inspect credentials privately for local login.",
  );
}
