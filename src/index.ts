import { configuration } from "./config";
import { Provider } from "./provider";
import { Store } from "./storage/state";
import { fail, policy } from "./shared/http";
import type { Config, Env } from "./shared/types";
export { ProviderState } from "./storage/state";
export default {
  async fetch(r: Request, env: Env): Promise<Response> {
    let response: Response;
    let c: Config;
    try {
      c = configuration(env);
    } catch {
      return new Response(JSON.stringify({ error: "server_error" }), {
        status: 503,
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
        },
      });
    }
    try {
      const store = new Store(env.STATE.get(env.STATE.idFromName(c.issuer)));
      response = await new Provider(c, store).handle(r);
    } catch {
      response = fail("invalid_request");
    }
    const headers = new Headers(response.headers);
    headers.set("Cache-Control", "no-store");
    headers.set("Pragma", "no-cache");
    headers.set("X-Content-Type-Options", "nosniff");
    if (!headers.has("Referrer-Policy"))
      headers.set("Referrer-Policy", "no-referrer");
    if (!headers.has("Content-Security-Policy"))
      headers.set("Content-Security-Policy", policy);
    return new Response(response.body, { status: response.status, headers });
  },
} satisfies ExportedHandler<Env>;
