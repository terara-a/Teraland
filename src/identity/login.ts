import { form, fail, escape, policy } from "../shared/http";
import { hash, equal } from "../shared/crypto";
import {
  str,
  random,
  now,
  type Config,
  type AuthRequest,
} from "../shared/types";
import type { Store } from "../storage/state";
import { createSession } from "./session";
function cookie(c: Config, id: string, value: string, age = 300) {
  return `teraland_login_${id}=${value}; Path=${new URL(c.issuer).pathname.replace(/\/$/, "")}/login; HttpOnly; ${new URL(c.issuer).protocol === "https:" ? "Secure; " : ""}SameSite=Strict; Max-Age=${age}`;
}
export class Login {
  constructor(
    private c: Config,
    private store: Store,
    private complete: (
      a: AuthRequest,
      subject: string,
      authTime: number,
    ) => Promise<Response>,
  ) {}
  async form(a: AuthRequest) {
    const id = random();
    a.csrf = random();
    await this.store.call("put", "login:" + id, a);
    const origin = new URL(str(a.claims, "redirect_uri")).origin;
    const html = `<!doctype html><html lang="ja"><meta charset="utf-8"><title>Teraland ログイン</title><h1>Teraland</h1><p>${escape(str(a.claims, "client_id"))} にログインします。</p><form method="post" action="${escape(this.c.issuer + "/login")}"><input type="hidden" name="request_id" value="${id}"><label>ユーザー名 <input name="username" autocomplete="username" required></label><label>パスワード <input name="password" type="password" autocomplete="current-password" required></label><button type="submit">ログインして許可</button></form></html>`;
    return new Response(html, {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Set-Cookie": cookie(this.c, id, a.csrf),
        // no-referrer makes Chromium send Origin: null on a form POST.
        // Retain same-origin checks without leaking the request URL to the RP.
        "Referrer-Policy": "same-origin",
        "Content-Security-Policy": policy.replace(
          "form-action 'self'",
          `form-action 'self' ${origin}`,
        ),
      },
    });
  }
  async login(r: Request) {
    const f = await form(r),
      id = f.get("request_id") ?? "";
    if (!/^[a-f0-9-]{68}$/.test(id)) return fail("invalid_request");
    const csrf = (r.headers.get("cookie") ?? "")
      .split(";")
      .map((x) => x.trim())
      .find((x) => x.startsWith("teraland_login_" + id + "="))
      ?.split("=")[1];
    if (!csrf) return fail("invalid_request");
    const origin = r.headers.get("origin");
    if (origin && origin !== new URL(this.c.issuer).origin)
      return fail("access_denied", 403);
    const a = await this.store.call<AuthRequest | null>(
      "take",
      "login:" + id,
      undefined,
      { csrf },
    );
    if (!a) return fail("invalid_request");
    let response: Response;
    if (
      !(await equal(f.get("username") ?? "", this.c.username)) ||
      !(await equal(f.get("password") ?? "", this.c.password))
    )
      response = fail("access_denied", 401);
    else {
      const subject = await hash(this.c.issuer + "\0" + this.c.username),
        authTime = now();
      response = await this.complete(a, subject, authTime);
      if (a.client.static_client) {
        await createSession(this.c, this.store, response, subject, authTime);
      }
    }
    response.headers.append("Set-Cookie", cookie(this.c, id, "", 0));
    return response;
  }
}
