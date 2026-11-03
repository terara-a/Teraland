import { obj, requireThat, type ObjectMap } from "../shared/types";
export const scopeClaims: Record<string, string[]> = {
  profile: [
    "name",
    "family_name",
    "given_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "updated_at",
  ],
  email: ["email", "email_verified"],
  address: ["address"],
  phone: ["phone_number", "phone_number_verified"],
};
export function userClaims(raw = "{}"): ObjectMap {
  const profile = obj(JSON.parse(raw));
  const allowed = new Set(Object.values(scopeClaims).flat());
  for (const [k, v] of Object.entries(profile)) {
    requireThat(allowed.has(k), "Unsupported user claim");
    requireThat(
      k === "address"
        ? typeof v === "object" &&
            v !== null &&
            !Array.isArray(v) &&
            Object.values(v).every((x) => typeof x === "string")
        : k.endsWith("_verified")
          ? typeof v === "boolean"
          : k === "updated_at"
            ? typeof v === "number" && Number.isFinite(v) && v > 0
            : typeof v === "string",
      "Invalid user claim",
    );
  }
  return profile;
}
export function selectedClaims(
  profile: ObjectMap,
  scopes: string,
  requested: unknown,
): ObjectMap {
  const names = new Set(
    scopes.split(/\s+/).flatMap((s) => scopeClaims[s] ?? []),
  );
  for (const k of Object.keys(obj(requested))) names.add(k);
  return Object.fromEntries(
    Object.entries(profile).filter(([k]) => names.has(k)),
  );
}
