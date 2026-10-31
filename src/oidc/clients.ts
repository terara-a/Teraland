import { equal } from "../shared/crypto";
import {
  now,
  obj,
  str,
  strings,
  requireThat,
  type AuthRequest,
  type ObjectMap,
} from "../shared/types";
// A Federation adapter supplies verified RP metadata and authorization requests.
// Core never discovers trust paths or treats an untrusted URI as a static client.
export interface FederatedClients {
  relyingParty(id: string): Promise<ObjectMap>;
  request(raw: string, id: string): Promise<AuthRequest>;
}
export function staticClients(raw = "[]"): Record<string, ObjectMap> {
  const value: unknown = JSON.parse(raw);
  requireThat(
    Array.isArray(value) && value.length <= 32,
    "Invalid static clients",
  );
  const clients: Record<string, ObjectMap> = Object.create(null);
  for (const item of value) {
    const c = obj(item),
      id = str(c, "client_id"),
      redirects = strings(c.redirect_uris);
    requireThat(
      Object.keys(c).every((k) =>
        ["client_id", "client_secret", "redirect_uris"].includes(k),
      ),
      "Unsupported static client field",
    );
    requireThat(
      /^[A-Za-z0-9_-]{1,128}$/.test(id) && !Object.hasOwn(clients, id),
      "Invalid or duplicate client ID",
    );
    requireThat(
      str(c, "client_secret").length >= 32 &&
        redirects.length > 0 &&
        redirects.length <= 16,
      "Client secret and redirect URIs required",
    );
    for (const uri of redirects) {
      const u = new URL(uri);
      requireThat(
        u.protocol === "https:" && !u.username && !u.password && !u.hash,
        "Invalid static redirect URI",
      );
    }
    clients[id] = {
      client_id: id,
      client_secret: c.client_secret,
      redirect_uris: redirects,
      static_client: true,
      trust_exp: now() + 3600,
    };
  }
  return clients;
}
export function basicRequest(
  client: ObjectMap,
  params: URLSearchParams,
): AuthRequest {
  return { claims: Object.fromEntries(params), client, exp: now() + 300 };
}
export function basicCredentials(request: Request, form: URLSearchParams) {
  const header = request.headers.get("authorization");
  if (!header)
    return {
      id: form.get("client_id") ?? "",
      secret: form.get("client_secret") ?? "",
      basic: false,
    };
  const match = /^Basic ([A-Za-z0-9+/]+={0,2})$/i.exec(header);
  requireThat(
    match && !form.has("client_secret") && !form.has("client_assertion"),
    "Ambiguous client authentication",
  );
  const decoded = atob(match[1]),
    colon = decoded.indexOf(":");
  requireThat(colon >= 0, "Invalid basic credentials");
  const id = decodeURIComponent(decoded.slice(0, colon).replaceAll("+", " "));
  requireThat(
    !form.has("client_id") || form.get("client_id") === id,
    "Client ID mismatch",
  );
  return {
    id,
    secret: decodeURIComponent(decoded.slice(colon + 1).replaceAll("+", " ")),
    basic: true,
  };
}
export async function authenticateStatic(
  client: ObjectMap,
  secret: string,
  form: URLSearchParams,
) {
  requireThat(
    !form.has("client_assertion") &&
      secret &&
      (await equal(secret, str(client, "client_secret"))),
    "Invalid client authentication",
  );
}
