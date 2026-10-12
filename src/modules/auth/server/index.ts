export { AuthError } from "@/modules/auth/interface";
export {
  assertMutationOrigin,
  authCookieOptions,
  createAuthFreshnessPolicy,
  createAuthPolicy,
  resolveReturnPath,
} from "@/modules/auth/policy";
export { fingerprintAuthValue } from "@/modules/auth/server/crypto";
export { createLogoutVerifier } from "@/modules/auth/server/logout";
export { createProofReplayStore } from "@/modules/auth/server/proof";
export { createResourceAuth } from "@/modules/auth/server/resource";
export { createIdentityCache } from "@/modules/auth/server/identity-cache";
export { createOAuthIdentityValidator } from "@/modules/auth/server/identity";
export { createSessionGrantGuard } from "@/modules/auth/server/grant-guard";
export { matchesAuthRevocation } from "@/modules/auth/server/revocation";
export type {
  AuthErrorCode,
  AuthIdentity,
  AuthPolicy,
  AuthFreshness,
  AuthFreshnessInput,
  VerifiedLogout,
  LogoutStorage,
  LogoutVerifierOptions,
  ProofStorage,
  ResourceAuthOptions,
  IdentityCacheOptions,
  IdentityCacheInput,
  OAuthIdentityValidatorOptions,
  AuthSessionBinding,
  SessionGrantGuardOptions,
  AuthRevocation,
  AuthRevocationIdentity,
} from "@/utils/interface";
