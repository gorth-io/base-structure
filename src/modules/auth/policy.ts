import { AuthError, type AuthPolicy } from "./interface";

export function createAuthPolicy(
  overrides: Partial<AuthPolicy> = {},
): Readonly<AuthPolicy> {
  const policy: AuthPolicy = {
    sessionMaxAgeMs: 7 * 86_400_000,
    transactionMaxAgeMs: 120_000,
    identityMaxAgeMs: 120_000,
    refreshLeewayMs: 30_000,
    clockToleranceSeconds: 5,
    logoutMaxAgeSeconds: 120,
    revocationRetentionMs: 7 * 86_400_000 + 30_000,
    ...overrides,
  };
  if (
    Object.values(policy).some(
      (value) => !Number.isSafeInteger(value) || value < 0,
    ) ||
    !policy.sessionMaxAgeMs ||
    !policy.transactionMaxAgeMs ||
    !policy.logoutMaxAgeSeconds ||
    policy.transactionMaxAgeMs > 600_000 ||
    policy.clockToleranceSeconds > 60 ||
    policy.identityMaxAgeMs > 300_000 ||
    policy.revocationRetentionMs <
      policy.sessionMaxAgeMs + policy.clockToleranceSeconds * 1000 ||
    policy.revocationRetentionMs <
      (policy.logoutMaxAgeSeconds + policy.clockToleranceSeconds) * 1000
  ) {
    throw new AuthError("invalid_configuration");
  }
  return Object.freeze(policy);
}

export function resolveReturnPath(value: string = "/"): string {
  // Also reject browser-normalized backslashes, controls, and protocol-relative URLs.
  if (
    value.length > 2048 ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    /[\\\u0000-\u0020\u007f]/.test(value)
  )
    throw new AuthError("rejected");
  const url = new URL(value, "https://app.invalid");
  if (url.origin !== "https://app.invalid") throw new AuthError("rejected");
  return url.pathname + url.search + url.hash;
}

export function assertMutationOrigin(
  headers: Headers,
  allowedOrigins: readonly string[],
): void {
  const origin = headers.get("origin");
  if (
    !origin ||
    !allowedOrigins.includes(origin) ||
    headers.get("sec-fetch-site") === "cross-site"
  ) {
    throw new AuthError("rejected");
  }
  for (const allowed of allowedOrigins) {
    if (new URL(allowed).origin !== allowed)
      throw new AuthError("invalid_configuration");
  }
}

export function authCookieOptions(options: {
  secure: boolean;
  maxAgeSeconds: number;
  path?: string;
}) {
  if (
    !Number.isSafeInteger(options.maxAgeSeconds) ||
    options.maxAgeSeconds < 0 ||
    (!options.path?.startsWith("/") && options.path !== undefined)
  ) {
    throw new AuthError("invalid_configuration");
  }
  // Host-only; each app owns its cookie. Reuse these attributes when deleting it.
  return {
    httpOnly: true,
    secure: options.secure,
    sameSite: "lax" as const,
    path: options.path ?? "/",
    maxAge: options.maxAgeSeconds,
  };
}
