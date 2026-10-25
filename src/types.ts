import type { JWK } from "jose";
export type ObjectMap = Record<string, unknown>;
export interface JWKS {
  keys: JWK[];
}
export interface Env {
  ISSUER: string;
  SIGNING_JWK: string;
  ENCRYPTION_JWK: string;
  TERALAND_USERNAME: string;
  TERALAND_PASSWORD: string;
  FEDERATION_HOSTS: string;
  TRUST_ANCHORS: string;
  STATE: DurableObjectNamespace;
  DEV_MODE?: string;
}
export interface Config {
  issuer: string;
  signing: JWK;
  encryption: JWK;
  username: string;
  password: string;
  hosts: string[];
  anchors: Record<string, JWKS>;
}
export interface AuthRequest {
  claims: ObjectMap;
  client: ObjectMap;
  exp: number;
  csrf?: string;
}
export interface Grant {
  client: string;
  redirect: string;
  nonce: string;
  scope: string;
  challenge: string;
  subject: string;
  authTime: number;
  exp: number;
}
export interface Entry {
  exp: number;
  [key: string]: unknown;
}
export const now = () => Math.floor(Date.now() / 1000);
export const obj = (v: unknown): ObjectMap =>
  typeof v === "object" && v !== null && !Array.isArray(v)
    ? (v as ObjectMap)
    : {};
export const str = (m: ObjectMap, k: string) =>
  typeof m[k] === "string" ? (m[k] as string) : "";
export const num = (m: ObjectMap, k: string) =>
  typeof m[k] === "number" && Number.isFinite(m[k]) ? (m[k] as number) : 0;
export function strings(v: unknown): string[] {
  if (typeof v === "string") return [v];
  if (Array.isArray(v) && v.every((x) => typeof x === "string")) return v;
  return [];
}
export const has = (v: unknown, s: string) => strings(v).includes(s);
export function requireThat(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}
export const random = () =>
  crypto.randomUUID() + crypto.randomUUID().replaceAll("-", "");
export function validTimes(m: ObjectMap, iat = false) {
  const exp = num(m, "exp");
  requireThat(exp > now(), "missing or expired exp");
  requireThat(
    !iat ||
      (num(m, "iat") > 0 && num(m, "iat") <= now() + 30 && num(m, "iat") < exp),
    "invalid iat",
  );
  requireThat(num(m, "nbf") <= now() + 30, "JWT not yet valid");
}
