import { AuthError } from "@/modules/auth/interface";
import type {
  AuthSessionBinding,
  SessionGrantGuardOptions,
} from "@/utils/interface";

/** Surround SDK getAccessToken/proxy operations; never implement token refresh here. */
export function createSessionGrantGuard(options: SessionGrantGuardOptions) {
  const now = options.now ?? Date.now;
  async function read(): Promise<Readonly<AuthSessionBinding>> {
    const value = await options.read();
    const time = now();
    if (!Number.isSafeInteger(time) || time < 0)
      throw new AuthError("invalid_configuration");
    if (
      !value ||
      [value.id, value.userId, value.subject].some(
        (identifier) =>
          typeof identifier !== "string" ||
          !identifier ||
          identifier.length > 255,
      ) ||
      (value.sid !== undefined &&
        (typeof value.sid !== "string" ||
          !value.sid ||
          value.sid.length > 255)) ||
      !Number.isSafeInteger(value.expiresAt) ||
      value.expiresAt <= time
    )
      throw new AuthError("rejected");
    const binding = Object.freeze({ ...value });
    await options.assertAllowed(binding);
    return binding;
  }
  return {
    async run<Value>(
      operation: (binding: Readonly<AuthSessionBinding>) => Promise<Value>,
      signal?: AbortSignal,
    ): Promise<Value> {
      try {
        signal?.throwIfAborted();
        const before = await read();
        signal?.throwIfAborted();
        const result = await operation(before);
        signal?.throwIfAborted();
        const after = await read();
        if (
          before.id !== after.id ||
          before.userId !== after.userId ||
          before.subject !== after.subject ||
          before.sid !== after.sid
        )
          throw new AuthError("rejected");
        signal?.throwIfAborted();
        return result;
      } catch (error) {
        if (signal?.aborted) throw new AuthError("cancelled");
        if (error instanceof AuthError) throw error;
        throw new AuthError("unavailable");
      }
    },
  };
}
