import { hash } from "../shared/crypto";
import { random, now, type Config, type ObjectMap } from "../shared/types";
import type { Store } from "../storage/state";
export async function readSession(r: Request, store: Store) {
  const sessionId = (r.headers.get("cookie") ?? "")
    .split(";")
    .map((x) => x.trim())
    .find((x) => x.startsWith("teraland_session="))
    ?.slice("teraland_session=".length);
  return sessionId && /^[a-f0-9-]{68}$/.test(sessionId)
    ? await store.call<ObjectMap | null>(
        "get",
        "session:" + (await hash(sessionId)),
      )
    : null;
}
export async function createSession(
  c: Config,
  store: Store,
  response: Response,
  subject: string,
  authTime: number,
) {
  const session = random();
  await store.call("put", "session:" + (await hash(session)), {
    subject,
    authTime,
    exp: now() + 3600,
  });
  response.headers.append(
    "Set-Cookie",
    `teraland_session=${session}; Path=${new URL(c.issuer).pathname.replace(/\/$/, "")}/; HttpOnly; ${new URL(c.issuer).protocol === "https:" ? "Secure; " : ""}SameSite=Lax; Max-Age=3600`,
  );
}
