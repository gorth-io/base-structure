import type { AuthErrorCode } from "@/utils/interface";

/** Safe to expose without a provider response, cause, request body, or token. */
export class AuthError extends Error {
  constructor(public readonly code: AuthErrorCode) {
    super(`Authentication ${code.replaceAll("_", " ")}`);
    this.name = "AuthError";
  }
}

export type {
  AuthErrorCode,
  AuthIdentity,
  AuthPolicy,
  PublicSession,
} from "@/utils/interface";
