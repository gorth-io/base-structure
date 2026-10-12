/** SDK owns login/useSession/signOut. This entry only coordinates request retries. */
export {
  createAuthRetry,
  waitForAuthOperation,
} from "@/modules/auth/client/retry";
export type { AuthRetryInput, AuthRetryOptions } from "@/utils/interface";
export { AuthError } from "@/modules/auth/interface";
export type {
  AuthErrorCode,
  AuthPolicy,
  AuthFreshness,
  AuthFreshnessInput,
} from "@/utils/interface";
export {
  createAuthFreshnessPolicy,
  createAuthPolicy,
} from "@/modules/auth/policy";
