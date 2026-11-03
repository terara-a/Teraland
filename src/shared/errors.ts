// Public descriptions are fixed text: never expose JWT contents, URLs, keys or
// low-level exception messages in authorization error pages.
export const requestErrors = {
  malformed_request: "The request object could not be decoded or decrypted.",
  invalid_type: "The request object has an invalid JWT type.",
  invalid_client_id: "The request contains a missing or mismatched client_id.",
  invalid_iss:
    "The request object iss claim is missing or does not match client_id.",
  untrusted_client:
    "The client metadata or federation trust could not be verified.",
  invalid_signature:
    "The request object signature or signing algorithm is invalid.",
  invalid_exp:
    "The request object has a missing, invalid or expired exp claim.",
  invalid_nbf: "The request object is not yet valid (nbf).",
  forbidden_sub: "The request object must not contain a sub claim.",
  invalid_aud: "The request object has a missing or invalid aud claim.",
  invalid_redirect_uri: "The redirect_uri is not registered for this client.",
  invalid_response_type: "Only the code response_type is supported.",
  invalid_scope: "The requested scope is not supported.",
  invalid_response_mode: "The requested response_mode is not supported.",
  invalid_pkce: "The request requires a valid S256 PKCE challenge.",
  invalid_jti: "The request object has a missing or invalid jti claim.",
  replayed_jti: "The request object jti has already been used.",
  expired_trust: "The federation trust has expired.",
  invalid_request_uri:
    "The pushed request is invalid, expired or already used.",
  invalid_request: "The authorization request is invalid.",
} as const;
export type RequestErrorReason = keyof typeof requestErrors;
export class RequestObjectError extends Error {
  constructor(public readonly reason: RequestErrorReason) {
    super(requestErrors[reason]);
  }
}
export class ReplayError extends Error {}
export function requestCheck(
  value: unknown,
  reason: RequestErrorReason,
): asserts value {
  if (!value) throw new RequestObjectError(reason);
}
