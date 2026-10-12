import { AuthError } from "@/modules/auth/interface";
import type { AuthRevocation, AuthRevocationIdentity } from "@/utils/interface";

/** Both sid/sub must match when supplied. Subject-only events use iat's entire second. */
export function matchesAuthRevocation(
  marker: AuthRevocation,
  identity: AuthRevocationIdentity,
  now: number = Date.now(),
): boolean {
  if (
    (!marker.sid && !marker.subject) ||
    !identity.subject ||
    [marker.issuedAt, marker.expiresAt, identity.issuedAt, now].some(
      (value) => !Number.isSafeInteger(value) || value < 0,
    )
  )
    throw new AuthError("rejected");
  return (
    marker.expiresAt > now &&
    (!marker.subject || marker.subject === identity.subject) &&
    (!marker.sid || marker.sid === identity.sid) &&
    (!!marker.sid ||
      Math.floor(identity.issuedAt / 1000) <=
        Math.floor(marker.issuedAt / 1000))
  );
}
