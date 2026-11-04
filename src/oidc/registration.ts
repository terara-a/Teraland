import { equal, hash, keySet } from "../shared/crypto";
import { fail, json, limitedText } from "../shared/http";
import {
  now,
  obj,
  random,
  requireThat,
  str,
  type Config,
  type ObjectMap,
} from "../shared/types";
import type { Store } from "../storage/state";

function https(value: unknown, fragment = false) {
  requireThat(typeof value === "string" && value.length <= 2048, "Invalid URI");
  const u = new URL(value);
  requireThat(
    u.protocol === "https:" &&
      !u.username &&
      !u.password &&
      (fragment || !u.hash),
    "Invalid URI",
  );
  return value;
}
function list(value: unknown, max: number) {
  requireThat(
    Array.isArray(value) &&
      value.length > 0 &&
      value.length <= max &&
      value.every((x) => typeof x === "string"),
    "Invalid list",
  );
  return value as string[];
}
function metadata(input: ObjectMap): ObjectMap {
  const response: ObjectMap = {
    application_type: "web",
    response_types: ["code"],
    grant_types: ["authorization_code"],
    token_endpoint_auth_method: "client_secret_basic",
    id_token_signed_response_alg: "RS256",
    subject_type: "public",
  };
  for (const [field, expected] of Object.entries(response)) {
    if (!(field in input)) continue;
    if (field === "grant_types") {
      const grants = list(input.grant_types, 2);
      requireThat(
        grants.includes("authorization_code") &&
          grants.every((x) =>
            ["authorization_code", "refresh_token"].includes(x),
          ),
        "Unsupported flow",
      );
      // Negotiate the supported subset explicitly in the registration response.
      // Registration does not promise refresh tokens merely because requested.
      continue;
    }
    if (field === "token_endpoint_auth_method")
      requireThat(
        ["client_secret_basic", "client_secret_post"].includes(
          str(input, field),
        ),
        "Unsupported authentication",
      );
    else if (Array.isArray(expected))
      requireThat(
        JSON.stringify(input[field]) === JSON.stringify(expected),
        "Unsupported flow",
      );
    else requireThat(input[field] === expected, "Unsupported metadata");
    response[field] = input[field];
  }
  for (const field of [
    "jwks_uri",
    "sector_identifier_uri",
    "id_token_encrypted_response_alg",
    "id_token_encrypted_response_enc",
    "userinfo_signed_response_alg",
    "userinfo_encrypted_response_alg",
    "userinfo_encrypted_response_enc",
    "request_object_signing_alg",
    "request_object_encryption_alg",
    "request_object_encryption_enc",
    "default_max_age",
    "require_auth_time",
    "default_acr_values",
    "initiate_login_uri",
    "software_statement",
  ])
    requireThat(!(field in input), "Unsupported metadata");
  if ("jwks" in input) response.jwks = keySet(input.jwks);
  if ("client_name" in input) {
    requireThat(
      typeof input.client_name === "string" && input.client_name.length <= 200,
      "Invalid name",
    );
    response.client_name = input.client_name;
  }
  if ("contacts" in input) {
    const contacts = list(input.contacts, 8);
    requireThat(
      contacts.every((x) => x.length <= 254 && /^[^\s@]+@[^\s@]+$/.test(x)),
      "Invalid contacts",
    );
    response.contacts = contacts;
  }
  // These are registration metadata only: neither registration nor authorization
  // dereferences them. Discovery continues to advertise request_uri as unsupported.
  if ("request_uris" in input)
    response.request_uris = list(input.request_uris, 16).map((x) =>
      https(x, true),
    );
  return response;
}
export async function register(c: Config, store: Store, r: Request) {
  if (!c.registrationToken) return fail("not_found", 404);
  const bearer = /^Bearer (\S+)$/i.exec(r.headers.get("authorization") ?? "");
  if (!bearer || !(await equal(bearer[1], c.registrationToken)))
    return new Response(JSON.stringify({ error: "invalid_token" }), {
      status: 401,
      headers: {
        "Content-Type": "application/json",
        "WWW-Authenticate": 'Bearer error="invalid_token"',
      },
    });
  if (
    new URL(r.url).search ||
    r.headers.get("content-type")?.split(";")[0].trim() !== "application/json"
  )
    return fail("invalid_client_metadata");
  let input: ObjectMap;
  try {
    const value: unknown = JSON.parse(await limitedText(r.body, 16384));
    requireThat(
      value !== null && typeof value === "object" && !Array.isArray(value),
      "Invalid metadata",
    );
    input = obj(value);
  } catch {
    return fail("invalid_client_metadata");
  }
  let redirects: string[];
  try {
    redirects = list(input.redirect_uris, 16).map((x) => https(x));
  } catch {
    return fail("invalid_redirect_uri");
  }
  let registered: ObjectMap;
  try {
    registered = metadata(input);
  } catch {
    return fail("invalid_client_metadata");
  }
  const id = "dcr_" + random(),
    secret = random(),
    issued = now(),
    exp = issued + 86400;
  const client = {
    ...registered,
    redirect_uris: redirects,
    client_id: id,
    client_secret_hash: await hash(secret),
    dynamic_client: true,
    trust_exp: exp,
    exp,
  };
  if (!(await store.call("register", "client:" + (await hash(id)), client)))
    return fail("temporarily_unavailable", 503);
  return json(
    {
      ...registered,
      redirect_uris: redirects,
      client_id: id,
      client_secret: secret,
      client_id_issued_at: issued,
      client_secret_expires_at: exp,
    },
    201,
  );
}
