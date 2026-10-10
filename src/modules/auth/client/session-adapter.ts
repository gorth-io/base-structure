import type { AuthClientAdapter } from "@/modules/auth/client/index";
import { AuthError } from "@/modules/auth/interface";
import { formatEpochMilliseconds } from "@/utils/formatter";
import type {
  SessionAuthAdapterOptions,
  SessionSdkResult,
} from "@/utils/interface";

/** Better Auth/Neon-style session adapter; imports neither SDK nor React/env/DB. */
export function createSessionAuthAdapter<ProviderUser, User>(
  options: SessionAuthAdapterOptions<ProviderUser, User>,
): AuthClientAdapter<User> {
  const now = options.now ?? Date.now;
  async function operation<Result>(
    signal: AbortSignal,
    run: () => Promise<Result>,
  ) {
    try {
      signal.throwIfAborted();
      const result = await run();
      signal.throwIfAborted();
      return result;
    } catch (error) {
      if (signal.aborted) throw new AuthError("cancelled");
      if (error instanceof AuthError) throw error;
      // Do not let provider errors (which may contain credentials) escape.
      let code: AuthError["code"] = "unavailable";
      try {
        code = options.errorCode?.(error) ?? code;
      } catch {
        /* fail closed */
      }
      if (
        ![
          "invalid_configuration",
          "rejected",
          "forbidden",
          "unavailable",
          "cancelled",
        ].includes(code)
      )
        code = "unavailable";
      throw new AuthError(code);
    }
  }
  function check(result: SessionSdkResult<unknown>) {
    if (result.error != null) {
      // Wrapped by operation() so the caller can classify it without leaking it.
      throw result.error;
    }
  }
  return {
    read: (signal) =>
      operation(signal, async () => {
        const result = await options.getSession(signal);
        check(result);
        if (result.data == null) return null;
        const value = result.data.session.expiresAt;
        const expiresAt = formatEpochMilliseconds(value);
        if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0)
          throw new AuthError("rejected");
        if (expiresAt <= now()) return null;
        return { user: options.mapUser(result.data.user), expiresAt };
      }),
    login: (input, signal) =>
      operation(signal, () => options.login(input, signal)),
    logout: (signal) =>
      operation(signal, async () => {
        check(await options.signOut(signal));
      }),
  };
}

export type {
  SessionAuthAdapterOptions,
  SessionSdkResult,
  SessionSdkSession,
} from "@/utils/interface";
