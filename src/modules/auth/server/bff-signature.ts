import { AuthError } from "@/modules/auth/interface";
import { formatHexBytes } from "@/utils/formatter";
import type {
  BffSignatureOptions,
  BffVerifierOptions,
} from "@/utils/interface";
import { base64url } from "jose";

const encoder = new TextEncoder();
function validate(options: BffSignatureOptions) {
  if (
    !/^[a-zA-Z0-9._:-]{1,128}$/.test(options.context) ||
    !Number.isSafeInteger(options.maxBodyBytes ?? 1_048_576) ||
    (options.maxBodyBytes ?? 1_048_576) < 0 ||
    (options.maxBodyBytes ?? 1_048_576) > 8_388_608
  )
    throw new AuthError("invalid_configuration");
}
async function signingKey(options: BffSignatureOptions) {
  try {
    const bytes = await options.key();
    if (!(bytes instanceof Uint8Array) || bytes.length < 32)
      throw new AuthError("invalid_configuration");
    return await crypto.subtle.importKey(
      "raw",
      new Uint8Array(bytes),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"],
    );
  } catch (error) {
    if (error instanceof AuthError) throw error;
    throw new AuthError("unavailable");
  }
}
async function canonical(
  options: BffSignatureOptions,
  method: string,
  target: string,
  timestamp: string,
  nonce: string,
  body: string,
) {
  let url: URL;
  try {
    url = new URL(target, "https://bff.invalid");
  } catch {
    throw new AuthError("rejected");
  }
  if (
    url.origin !== "https://bff.invalid" ||
    url.hash ||
    url.username ||
    url.password ||
    !target.startsWith("/") ||
    target.startsWith("//") ||
    target.includes("\\") ||
    target !== url.pathname + url.search ||
    method !== "POST"
  )
    throw new AuthError("rejected");
  const bytes = encoder.encode(body);
  if (bytes.length > (options.maxBodyBytes ?? 1_048_576))
    throw new AuthError("rejected");
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return encoder.encode(
    [
      options.context,
      method,
      target,
      timestamp,
      nonce,
      formatHexBytes(digest),
    ].join("\n"),
  );
}

/** Server-side BFF signer. No env reads, global secret, cookie handling or DB connection. */
export function createBffSigner(options: BffSignatureOptions) {
  validate(options);
  return async function signBffRequest(target: string, body: string) {
    const timestamp = String((options.now ?? Date.now)());
    if (!/^\d{13}$/.test(timestamp))
      throw new AuthError("invalid_configuration");
    const nonce = base64url.encode(crypto.getRandomValues(new Uint8Array(32)));
    const signature = await crypto.subtle.sign(
      "HMAC",
      await signingKey(options),
      await canonical(options, "POST", target, timestamp, nonce, body),
    );
    return {
      "x-bff-time": timestamp,
      "x-bff-nonce": nonce,
      "x-bff-signature": formatHexBytes(signature),
    };
  };
}

/** Persistent proof consumption occurs only AFTER signature verification. */
export function createBffVerifier(options: BffVerifierOptions) {
  validate(options);
  const age = options.maxAgeMs ?? 30_000;
  if (!Number.isSafeInteger(age) || age < 1 || age > 60_000)
    throw new AuthError("invalid_configuration");
  return async function verifyBffRequest(request: Request, body: string) {
    const now = (options.now ?? Date.now)();
    const timestamp = request.headers.get("x-bff-time") ?? "";
    const nonce = request.headers.get("x-bff-nonce") ?? "";
    const signature = request.headers.get("x-bff-signature") ?? "";
    if (
      request.method !== "POST" ||
      !/^\d{13}$/.test(timestamp) ||
      Math.abs(now - Number(timestamp)) > age ||
      !/^[A-Za-z0-9_-]{43}$/.test(nonce) ||
      !/^[a-f0-9]{64}$/.test(signature)
    )
      throw new AuthError("rejected");
    const url = new URL(request.url);
    const bytes = Uint8Array.from(signature.match(/../g)!, (pair) =>
      Number.parseInt(pair, 16),
    );
    const valid = await crypto.subtle.verify(
      "HMAC",
      await signingKey(options),
      bytes,
      await canonical(
        options,
        request.method,
        url.pathname + url.search,
        timestamp,
        nonce,
        body,
      ),
    );
    if (!valid) throw new AuthError("rejected");
    const proofKey =
      "bff:" +
      formatHexBytes(
        await crypto.subtle.digest("SHA-256", encoder.encode(nonce)),
      );
    try {
      // A future-dated proof can remain valid for 2*age; retain through that bound.
      if (!(await options.proof.consume(proofKey, now + 2 * age + 1)))
        throw new AuthError("rejected");
    } catch (error) {
      if (error instanceof AuthError) throw error;
      throw new AuthError("unavailable");
    }
  };
}

export type {
  BffSignatureOptions,
  BffVerifierOptions,
} from "@/utils/interface";
