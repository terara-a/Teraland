import { passwordAcr } from "../identity/method";
import type { Config } from "../shared/types";
export function metadata(c: Config) {
  return {
    issuer: c.issuer,
    authorization_endpoint: c.issuer + "/authorize",
    token_endpoint: c.issuer + "/token",
    userinfo_endpoint: c.issuer + "/userinfo",
    jwks_uri: c.issuer + "/jwks",
    pushed_authorization_request_endpoint: c.issuer + "/par",
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code"],
    subject_types_supported: ["public"],
    scopes_supported: [
      "openid",
      "profile",
      ...(Object.keys(c.clients).length ? ["email", "address", "phone"] : []),
    ],
    claims_supported: [
      "iss",
      "sub",
      "aud",
      "exp",
      "iat",
      "auth_time",
      "nonce",
      ...Object.keys(c.userClaims),
      ...(Object.keys(c.clients).length ? ["acr", "amr"] : []),
    ],
    claims_parameter_supported: Object.keys(c.clients).length > 0,
    ...(Object.keys(c.clients).length
      ? { acr_values_supported: [passwordAcr] }
      : {}),
    id_token_signing_alg_values_supported: ["RS256"],
    request_object_signing_alg_values_supported: ["RS256", "PS256", "ES256"],
    token_endpoint_auth_methods_supported: [
      "private_key_jwt",
      ...(Object.keys(c.clients).length
        ? ["client_secret_basic", "client_secret_post"]
        : []),
    ],
    token_endpoint_auth_signing_alg_values_supported: [
      "RS256",
      "PS256",
      "ES256",
    ],
    request_parameter_supported: true,
    request_uri_parameter_supported: false,
    require_signed_request_object: Object.keys(c.clients).length === 0,
    client_registration_types_supported: ["automatic"],
    code_challenge_methods_supported: ["S256"],
    authorization_response_iss_parameter_supported: true,
    request_object_encryption_alg_values_supported: [
      "RSA-OAEP-256",
      "RSA-OAEP",
    ],
    request_object_encryption_enc_values_supported: ["A256GCM"],
  };
}
