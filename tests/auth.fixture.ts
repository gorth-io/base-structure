import { matchesAuthRevocation } from "../src/modules/auth/server/revocation";
import type { VerifiedLogout, LogoutStorage } from "../src/utils/interface";

/** Test only; deployed adapters must make receipt/revocation/session deletion atomic. */
export function revocationFixture() {
  const receipts = new Map<string, VerifiedLogout>();
  const revocation: LogoutStorage = {
    async isRevoked(input) {
      return [...receipts.values()].some((marker) =>
        matchesAuthRevocation(
          {
            subject: marker.subject,
            sid: marker.sid,
            issuedAt: marker.issuedAt,
            expiresAt: marker.revokeUntil,
          },
          input,
          input.now,
        ),
      );
    },
    async apply(logout) {
      if (receipts.has(logout.jti)) return false;
      receipts.set(logout.jti, logout);
      return true;
    },
  };
  return { revocation, receipts };
}
export function deferred<Value>() {
  let resolve!: (value: Value) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<Value>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
