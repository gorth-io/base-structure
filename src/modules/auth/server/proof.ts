import { AuthError } from "@/modules/auth/interface";
import type { ProofStorage } from "@/modules/auth/server/interface";
import type { DpopReplayStore } from "better-auth/oauth2";

/** Feed this adapter to Better Auth's request verifier; it is NOT proof verification itself. */
export function createProofReplayStore(
  storage: ProofStorage,
  now: () => number = Date.now,
): DpopReplayStore {
  return {
    async reserve(reservation) {
      const { key } = reservation;
      const expiresAt = reservation.expiresAt.getTime();
      if (
        !key ||
        key.length > 2048 ||
        !Number.isFinite(expiresAt) ||
        expiresAt <= now()
      )
        throw new AuthError("rejected");
      try {
        return await storage.consume(key, expiresAt);
      } catch {
        throw new AuthError("unavailable");
      }
    },
  };
}
