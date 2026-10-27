import { ReplayError } from "./errors";
import { DurableObject } from "cloudflare:workers";
import { now, obj, requireThat, type Entry } from "./types";
// Only the Worker can reach this binding. Every read/consume is transactional;
// isolate restarts and simultaneous requests cannot reuse a code or JTI.
export class ProviderState extends DurableObject {
  async fetch(request: Request): Promise<Response> {
    const m = obj(await request.json());
    const key = m.key;
    requireThat(
      typeof key === "string" && key.length <= 512,
      "invalid state key",
    );
    const result = await this.ctx.storage.transaction(async (tx) => {
      const current = await tx.get<Entry>(key);
      const live = current && current.exp > now() ? current : undefined;
      switch (m.op) {
        case "put":
        case "once": {
          const value = obj(m.value);
          requireThat(
            typeof value.exp === "number" && value.exp > now(),
            "expired state",
          );
          if (m.op === "once" && live) return false;
          await tx.put(key, value);
          return true;
        }
        case "get":
          return live ?? null;
        case "take": {
          if (!live) return null;
          const match = obj(m.match);
          if (!Object.entries(match).every(([k, v]) => live[k] === v))
            return null;
          await tx.delete(key);
          return live;
        }
        default:
          throw new Error("invalid state operation");
      }
    });
    // Persistent alarm prunes expired records even when the provider is idle.
    if ((await this.ctx.storage.getAlarm()) === null)
      await this.ctx.storage.setAlarm(Date.now() + 60000);
    return Response.json(result);
  }
  async alarm() {
    // Bounded pages prevent a full-store scan from monopolizing an invocation.
    let start: string | undefined;
    do {
      const page = await this.ctx.storage.list<Entry>({
        limit: 128,
        ...(start ? { startAfter: start } : {}),
      });
      for (const [key, value] of page)
        if (value.exp <= now()) await this.ctx.storage.delete(key);
      start = page.size === 128 ? [...page.keys()].at(-1) : undefined;
    } while (start);
    if ((await this.ctx.storage.list({ limit: 1 })).size)
      await this.ctx.storage.setAlarm(Date.now() + 60000);
  }
}
export class Store {
  constructor(private stub: DurableObjectStub) {}
  async call<T>(
    op: string,
    key: string,
    value?: unknown,
    match?: unknown,
  ): Promise<T> {
    const r = await this.stub.fetch("https://state.internal/", {
      method: "POST",
      body: JSON.stringify({ op, key, value, match }),
    });
    if (!r.ok) throw new Error("state unavailable");
    return r.json<T>();
  }
  async remember(kind: string, client: string, jti: string, exp: number) {
    requireThat(jti && jti.length <= 256, "missing jti");
    const { hash } = await import("./crypto");
    const remembered = await this.call(
      "once",
      "replay:" + (await hash(JSON.stringify([kind, client, jti]))),
      { exp },
    );
    if (!remembered) throw new ReplayError("replayed jti");
  }
}
