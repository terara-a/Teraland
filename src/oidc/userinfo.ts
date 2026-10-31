import { fail, json, limitedText } from "../shared/http";
import { hash } from "../shared/crypto";
import { obj, type ObjectMap } from "../shared/types";
import type { Store } from "../storage/state";
export async function userinfo(store: Store, r: Request) {
  const authorization = r.headers.get("authorization");
  const body =
    r.method === "POST" &&
    r.headers.get("content-type")?.split(";")[0].trim() ===
      "application/x-www-form-urlencoded"
      ? new URLSearchParams(await limitedText(r.body))
      : new URLSearchParams();
  if (
    new URL(r.url).searchParams.has("access_token") ||
    (authorization && body.has("access_token")) ||
    body.getAll("access_token").length > 1
  )
    return fail("invalid_request");
  const match = authorization ? /^Bearer (\S+)$/i.exec(authorization) : null;
  const token =
    match?.[1] ?? (!authorization ? body.get("access_token") : null);
  const a = token
    ? await store.call<ObjectMap | null>("get", "token:" + (await hash(token)))
    : null;
  return a
    ? json({ ...obj(a.userinfo), sub: a.subject })
    : new Response(JSON.stringify({ error: "invalid_token" }), {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "WWW-Authenticate": 'Bearer error="invalid_token"',
        },
      });
}
