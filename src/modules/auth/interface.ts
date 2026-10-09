/** Public identity projection. Provider roles never overwrite application roles. */
export interface AuthIdentity {
  subject: string;
  name?: string;
  email?: string;
  emailVerified?: boolean;
  username?: string | null;
  image?: string | null;
}

export interface PublicSession<User> {
  user: User;
  expiresAt: number;
}

export interface AuthPolicy {
  sessionMaxAgeMs: number;
  transactionMaxAgeMs: number;
  identityMaxAgeMs: number;
  refreshLeewayMs: number;
  clockToleranceSeconds: number;
  logoutMaxAgeSeconds: number;
  /** Cover the longest accepted access/app-session lifetime, not logout JWT expiry. */
  revocationRetentionMs: number;
}

export type AuthErrorCode =
  | "invalid_configuration"
  | "rejected"
  | "forbidden"
  | "unavailable"
  | "cancelled";

/** Safe to expose without a provider response, cause, request body, or token. */
export class AuthError extends Error {
  constructor(public readonly code: AuthErrorCode) {
    super(`Authentication ${code.replaceAll("_", " ")}`);
    this.name = "AuthError";
  }
}
