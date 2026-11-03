import { requestErrors, type RequestErrorReason } from "../shared/errors";
import {
  str,
  type Config,
  type AuthRequest,
  type ObjectMap,
} from "../shared/types";
export function authorizationFailure(
  reason: RequestErrorReason = "invalid_request",
) {
  // An invalid request never establishes a safe callback destination. Render
  // locally, with no cookies/forms/links and no reflection of request values.
  const code =
    reason === "invalid_request_uri"
      ? reason
      : reason === "invalid_request"
        ? reason
        : "invalid_request_object";
  const html = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Teraland — Invalid authorization request</title><h1>Authorization request rejected</h1><p>Error: <code>${code}</code></p><p id="authorization-error" data-error="${code}" data-reason="${reason}">${requestErrors[reason]}</p></html>`;
  return new Response(html, {
    status: 400,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy":
        "default-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
      "Referrer-Policy": "no-referrer",
    },
  });
}
export function callback(c: Config, a: AuthRequest, values: ObjectMap) {
  const u = new URL(str(a.claims, "redirect_uri"));
  for (const [k, v] of Object.entries(values)) u.searchParams.set(k, String(v));
  u.searchParams.set("iss", c.issuer);
  if (a.claims.state) u.searchParams.set("state", str(a.claims, "state"));
  return new Response(null, { status: 303, headers: { Location: u.href } });
}
