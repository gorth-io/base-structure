import type { AuthErrorCode } from "@/utils/interface";

/** Safe errors never include provider payloads, credentials or database causes. */
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
} from "@/utils/interface";
