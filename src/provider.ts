import type { Config } from "./shared/types";
import type { Store } from "./storage/state";
import { Federation } from "./federation";
import { entityConfiguration } from "./federation/discovery";
import { Login } from "./identity/login";
import { metadata } from "./oidc/discovery";
import { authorize } from "./oidc/authorization";
import { authorizationFailure } from "./oidc/responses";
import { issueCode } from "./oidc/code";
import { token } from "./oidc/token";
import { par } from "./oidc/par";
import { userinfo } from "./oidc/userinfo";
import { publicKey } from "./shared/crypto";
import { requireThat } from "./shared/types";
import { json, fail } from "./shared/http";
export class Provider {
  private clients: Federation;
  private login: Login;
  constructor(
    private c: Config,
    private store: Store,
  ) {
    this.clients = new Federation(c, store, AbortSignal.timeout(20000));
    this.login = new Login(c, store, (a, subject, authTime) =>
      issueCode(c, store, a, subject, authTime),
    );
  }
  async handle(r: Request): Promise<Response> {
    const c = this.c;
    const base = new URL(c.issuer).pathname.replace(/\/$/, "");
    const path = new URL(r.url).pathname.slice(base.length);
    requireThat(new URL(r.url).pathname.startsWith(base + "/"), "invalid path");
    if (path === "/healthz" && r.method === "GET")
      return json({ status: "ok" });
    if (path === "/.well-known/openid-configuration" && r.method === "GET")
      return json(metadata(c));
    if (path === "/jwks" && r.method === "GET")
      return json({ keys: [publicKey(c.signing), publicKey(c.encryption)] });
    if (path === "/.well-known/openid-federation" && r.method === "GET")
      return entityConfiguration(c);
    if (path === "/userinfo" && ["GET", "POST"].includes(r.method))
      return userinfo(this.store, r);
    if (path === "/authorize" && ["GET", "POST"].includes(r.method))
      return authorize(c, this.store, this.clients, this.login, r).catch(() =>
        authorizationFailure(),
      );
    if (path === "/par" && r.method === "POST")
      return par(c, this.store, this.clients, r);
    if (path === "/login" && r.method === "POST") return this.login.login(r);
    if (path === "/token" && r.method === "POST")
      return token(c, this.store, this.clients, r);
    return fail("not_found", 404);
  }
}
