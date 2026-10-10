export { AuthError } from "@/modules/auth/interface";
export type {
  AuthIdentity,
  AuthPolicy,
  PublicSession,
} from "@/modules/auth/interface";
export {
  assertMutationOrigin,
  authCookieOptions,
  createAuthFreshnessPolicy,
  createAuthPolicy,
  resolveReturnPath,
} from "@/modules/auth/policy";
export {
  createBffSigner,
  createBffVerifier,
} from "@/modules/auth/server/bff-signature";
export type {
  BffSignatureOptions,
  BffVerifierOptions,
} from "@/modules/auth/server/bff-signature";
export {
  createAuthCipher,
  fingerprintAuthValue,
} from "@/modules/auth/server/crypto";
export { createOidcDiscovery } from "@/modules/auth/server/discovery";
export type {
  OidcDiscoveryOptions,
  OidcMetadata,
} from "@/modules/auth/server/discovery";
export * from "@/modules/auth/server/interface";
export { createLogoutVerifier } from "@/modules/auth/server/logout";
export type { LogoutVerifierOptions } from "@/modules/auth/server/logout";
export {
  createOAuthProvider,
  validateOAuthConfig,
} from "@/modules/auth/server/oauth";
export { createProofReplayStore } from "@/modules/auth/server/proof";
export { createResourceAuth } from "@/modules/auth/server/resource";
export type { ResourceAuthOptions } from "@/modules/auth/server/resource";
export {
  loginTransactionSchema,
  oauthCredentialsSchema,
  oauthIdentitySchema,
  oauthTokenSchema,
} from "@/modules/auth/server/schema";
export { createSessionService } from "@/modules/auth/server/session";
export type { SessionServiceOptions } from "@/modules/auth/server/session";
export { createSessionBoundTransport } from "@/modules/auth/server/session-binding";
export type { SessionBoundTransportOptions } from "@/modules/auth/server/session-binding";
export type {
  AuthCipherOptions,
  AuthFreshness,
  AuthFreshnessInput,
  AuthReadInput,
  OidcLoadInput,
} from "@/utils/interface";
