import { AuthError } from "@/modules/auth/interface";
import { base64url } from "jose";

/** Hash cache keys; never store bearer credentials as Map keys. */
export async function fingerprintAuthValue(value: string): Promise<string> {
  try {
    return base64url.encode(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
      ),
    );
  } catch {
    throw new AuthError("unavailable");
  }
}
