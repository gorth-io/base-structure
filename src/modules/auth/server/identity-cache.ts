import { waitForAuthOperation } from "@/modules/auth/client/retry";
import { AuthError } from "@/modules/auth/interface";
import { fingerprintAuthValue } from "@/modules/auth/server/crypto";
import type {
  IdentityCacheInput,
  IdentityCacheOptions,
} from "@/utils/interface";

/** Identity freshness only. Each API still checks token/scopes, revocation and ACL. */
export function createIdentityCache<Value>(
  options: IdentityCacheOptions<Value>,
) {
  const now = options.now ?? Date.now;
  const ttl = options.maxAgeMs ?? 120_000;
  const capacity = options.capacity ?? 512;
  const maxPending = options.maxPending ?? capacity;
  const fingerprint = options.key ?? fingerprintAuthValue;
  if (
    ![ttl, capacity, maxPending].every(Number.isSafeInteger) ||
    ttl < 0 ||
    capacity < 1 ||
    maxPending < 1
  )
    throw new AuthError("invalid_configuration");
  const cache = new Map<string, { value: Value; expiresAt: number }>();
  const flights = new Map<
    string,
    { promise: Promise<Value>; marker: symbol }
  >();
  // Pending key derivation must also observe per-credential invalidation.
  const derivations = new Set<Set<string>>();
  let generation = 0;

  async function get(
    credential: string,
    input: IdentityCacheInput = {},
  ): Promise<Value> {
    input.signal?.throwIfAborted();
    if (!credential || credential.length > 32768)
      throw new AuthError("rejected");
    const version = generation;
    const invalidated = new Set<string>();
    derivations.add(invalidated);
    let key: string;
    try {
      key = await fingerprint(credential);
    } catch {
      throw new AuthError("unavailable");
    } finally {
      derivations.delete(invalidated);
    }
    input.signal?.throwIfAborted();
    if (version !== generation || invalidated.has(key))
      throw new AuthError("rejected");
    if (!key || key.length > 2048) throw new AuthError("invalid_configuration");
    const pending = flights.get(key);
    if (pending)
      return await waitForAuthOperation(pending.promise, input.signal);
    const cached = cache.get(key);
    if (!input.fresh && cached && cached.expiresAt > now()) return cached.value;
    cache.delete(key);
    if (flights.size >= maxPending) throw new AuthError("unavailable");
    const startedAt = now();
    const marker = Symbol();
    const operation = (async () => {
      await Promise.resolve(); // Register before a throwing/reentrant adapter.
      try {
        const value = await options.load(credential);
        if (version !== generation || flights.get(key)?.marker !== marker)
          throw new AuthError("rejected");
        const time = now();
        for (const [previous, entry] of cache)
          if (entry.expiresAt <= time) cache.delete(previous);
        // TTL starts before networking; never cache an already stale response.
        if (startedAt + ttl > time) {
          if (cache.size >= capacity) cache.delete(cache.keys().next().value!);
          cache.set(key, { value, expiresAt: startedAt + ttl });
        }
        return value;
      } catch (error) {
        if (error instanceof AuthError) throw error;
        throw new AuthError("unavailable");
      } finally {
        if (flights.get(key)?.marker === marker) flights.delete(key);
      }
    })();
    flights.set(key, { promise: operation, marker });
    return await waitForAuthOperation(operation, input.signal);
  }

  return {
    get,
    async forget(credential: string) {
      try {
        const key = await fingerprint(credential);
        for (const pending of derivations) pending.add(key);
        cache.delete(key);
        flights.delete(key); // Fence success/error from an earlier load.
      } catch {
        throw new AuthError("unavailable");
      }
    },
    clear() {
      generation++;
      cache.clear();
      flights.clear();
    },
  };
}
