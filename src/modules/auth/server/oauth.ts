import { base64url, jwtVerify, type JWTVerifyGetKey } from "jose";
import { AuthError } from "../interface";
import { createAuthPolicy, resolveReturnPath } from "../policy";
import {
  equalAuthValue,
  fingerprintAuthValue,
  randomAuthValue,
} from "./crypto";
import {
  loginTransactionSchema,
  oauthIdentitySchema,
  oauthTokenSchema,
} from "./schema";
import type {
  LoginTransaction,
  OAuthConfig,
  OAuthCredentials,
  OAuthOptions,
  VerifiedLogin,
} from "./interface";

function trustedUrl(value: string, allowLoopback: boolean): URL {
  try {
    const url = new URL(value);
    if (
      url.username ||
      url.password ||
      url.hash ||
      (url.protocol !== "https:" &&
        !(
          allowLoopback &&
          url.protocol === "http:" &&
          ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
        ))
    )
      throw new Error();
    return url;
  } catch {
    throw new AuthError("invalid_configuration");
  }
}

export function validateOAuthConfig(input: OAuthConfig): Readonly<OAuthConfig> {
  const local = input.allowLoopbackHttp === true;
  const issuer = trustedUrl(input.issuer, local);
  if (
    issuer.search ||
    !input.clientId ||
    input.clientId.length > 255 ||
    !input.scopes.includes("openid") ||
    input.scopes.some((scope) => !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope))
  ) {
    throw new AuthError("invalid_configuration");
  }
  for (const origin of input.endpointOrigins) {
    if (trustedUrl(origin, local).origin !== origin)
      throw new AuthError("invalid_configuration");
  }
  for (const value of Object.values(input.endpoints)) {
    const url = trustedUrl(value, local);
    if (url.search || !input.endpointOrigins.includes(url.origin))
      throw new AuthError("invalid_configuration");
  }
  for (const value of [input.redirectUri, input.postLogoutRedirectUri]) {
    if (trustedUrl(value, local).search)
      throw new AuthError("invalid_configuration");
  }
  for (const resource of input.resources ?? []) trustedUrl(resource, local);
  if (
    input.algorithms &&
    (!input.algorithms.length ||
      input.algorithms.some(
        (alg) => !["RS256", "ES256", "EdDSA"].includes(alg),
      ))
  ) {
    throw new AuthError("invalid_configuration");
  }
  return Object.freeze({
    ...input,
    endpoints: Object.freeze({ ...input.endpoints }),
    endpointOrigins: Object.freeze([...input.endpointOrigins]),
    scopes: Object.freeze([...input.scopes]),
    resources: Object.freeze([...(input.resources ?? [])]),
    algorithms: Object.freeze([
      ...(input.algorithms ?? (["RS256", "ES256", "EdDSA"] as const)),
    ]),
  });
}

export function createOAuthProvider(options: OAuthOptions) {
  const config = validateOAuthConfig(options.config);
  const policy = createAuthPolicy(options.policy);
  const now = options.now ?? Date.now;
  const binding = JSON.stringify([config.issuer, config.clientId]);

  async function request(
    url: string,
    method: "GET" | "POST",
    headers: Record<string, string>,
    body?: URLSearchParams,
    signal?: AbortSignal,
  ) {
    try {
      signal?.throwIfAborted();
      const response = await options.transport.request(url, {
        method,
        headers: { Accept: "application/json", ...headers },
        body,
        signal,
      });
      if (response.status >= 200 && response.status < 300) return response.data;
      const reason =
        response.data &&
        typeof response.data === "object" &&
        "error" in response.data
          ? response.data.error
          : null;
      if (
        response.status === 401 ||
        reason === "invalid_grant" ||
        reason === "invalid_token"
      )
        throw new AuthError("rejected");
      throw new AuthError("unavailable");
    } catch (error) {
      if (signal?.aborted) throw new AuthError("cancelled");
      if (error instanceof AuthError) throw error;
      throw new AuthError("unavailable");
    }
  }

  async function keys() {
    try {
      return await options.getVerificationKey();
    } catch {
      throw new AuthError("unavailable");
    }
  }

  async function verifyIdToken(
    token: string,
    accessToken: string,
    nonce: string,
    key: JWTVerifyGetKey,
    code?: string,
  ) {
    try {
      const result = await jwtVerify(token, key, {
        issuer: config.issuer,
        audience: config.clientId,
        algorithms: [...config.algorithms!],
        requiredClaims: [
          "iss",
          "aud",
          "sub",
          "iat",
          "exp",
          ...(code ? ["nonce"] : []),
        ],
        maxTokenAge: 300,
        clockTolerance: policy.clockToleranceSeconds,
        currentDate: new Date(now()),
      });
      const { payload, protectedHeader } = result;
      if (
        !payload.sub ||
        payload.sub.length > 255 ||
        (code
          ? payload.nonce !== nonce
          : payload.nonce !== undefined && payload.nonce !== nonce) ||
        (payload.azp !== undefined && payload.azp !== config.clientId) ||
        (Array.isArray(payload.aud) &&
          payload.aud.length > 1 &&
          payload.azp !== config.clientId) ||
        (payload.sid !== undefined &&
          (typeof payload.sid !== "string" ||
            !payload.sid ||
            payload.sid.length > 255))
      ) {
        throw new AuthError("rejected");
      }
      const hashAlgorithm =
        protectedHeader.alg === "EdDSA" ? "SHA-512" : "SHA-256";
      if (
        protectedHeader.alg === "EdDSA" &&
        (payload.at_hash !== undefined || payload.c_hash !== undefined) &&
        !("algorithm" in result.key && result.key.algorithm.name === "Ed25519")
      )
        throw new AuthError("rejected");
      for (const [claim, value] of [
        [payload.at_hash, accessToken],
        [payload.c_hash, code],
      ] as const) {
        if (claim === undefined) continue;
        if (typeof claim !== "string" || value === undefined)
          throw new AuthError("rejected");
        const digest = new Uint8Array(
          await crypto.subtle.digest(
            hashAlgorithm,
            new TextEncoder().encode(value),
          ),
        );
        if (
          !equalAuthValue(
            claim,
            base64url.encode(digest.slice(0, digest.length / 2)),
          )
        )
          throw new AuthError("rejected");
      }
      return payload;
    } catch {
      throw new AuthError("rejected");
    }
  }

  function tokenBody(body: URLSearchParams) {
    body.set("client_id", config.clientId);
    for (const resource of config.resources ?? [])
      body.append("resource", resource);
    return body;
  }

  async function tokens(body: URLSearchParams, signal?: AbortSignal) {
    const result = oauthTokenSchema.safeParse(
      await request(
        config.endpoints.token,
        "POST",
        { "Content-Type": "application/x-www-form-urlencoded" },
        tokenBody(body),
        signal,
      ),
    );
    if (!result.success) throw new AuthError("rejected");
    return result.data;
  }

  async function identity(credentials: OAuthCredentials, signal?: AbortSignal) {
    const result = oauthIdentitySchema.safeParse(
      await request(
        config.endpoints.userinfo,
        "GET",
        { Authorization: "Bearer " + credentials.accessToken },
        undefined,
        signal,
      ),
    );
    if (!result.success || result.data.sub !== credentials.subject)
      throw new AuthError("rejected");
    const data = result.data;
    // Deliberate projection: no roles, credentials, or arbitrary provider claims cross this boundary.
    return {
      subject: data.sub,
      name: data.name,
      email: data.email,
      emailVerified: data.email_verified,
      username: data.preferred_username,
      image: data.picture,
    };
  }

  async function startLogin(
    returnTo = "/",
    prompt?: "login" | "create" | "consent" | "select_account",
  ) {
    const transaction: LoginTransaction = {
      state: randomAuthValue(),
      verifier: randomAuthValue(),
      nonce: randomAuthValue(),
      issuer: config.issuer,
      clientId: config.clientId,
      redirectUri: config.redirectUri,
      returnTo: resolveReturnPath(returnTo),
      expiresAt: now() + policy.transactionMaxAgeMs,
    };
    let reserved: boolean;
    try {
      reserved = await options.loginStorage.reserve(
        await fingerprintAuthValue(transaction.state),
        transaction.expiresAt,
      );
    } catch {
      throw new AuthError("unavailable");
    }
    if (!reserved) throw new AuthError("unavailable");
    const url = new URL(config.endpoints.authorization);
    url.search = new URLSearchParams({
      response_type: "code",
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scopes.join(" "),
      state: transaction.state,
      nonce: transaction.nonce,
      code_challenge: await fingerprintAuthValue(transaction.verifier),
      code_challenge_method: "S256",
    }).toString();
    if (prompt) url.searchParams.set("prompt", prompt);
    for (const resource of config.resources ?? [])
      url.searchParams.append("resource", resource);
    return { url: url.href, transaction };
  }

  async function finishLogin(
    callback: string,
    stored: unknown,
    signal?: AbortSignal,
  ): Promise<VerifiedLogin> {
    const parsed = loginTransactionSchema.safeParse(stored);
    if (!parsed.success || callback.length > 8192)
      throw new AuthError("rejected");
    const transaction = parsed.data;
    let url: URL;
    try {
      url = new URL(callback);
    } catch {
      throw new AuthError("rejected");
    }
    const redirect = new URL(config.redirectUri);
    if (
      url.origin !== redirect.origin ||
      url.pathname !== redirect.pathname ||
      url.username ||
      url.password ||
      url.hash ||
      transaction.issuer !== config.issuer ||
      transaction.clientId !== config.clientId ||
      transaction.redirectUri !== config.redirectUri ||
      transaction.expiresAt <= now() ||
      transaction.expiresAt > now() + policy.transactionMaxAgeMs ||
      url.searchParams.getAll("state").length !== 1 ||
      !equalAuthValue(url.searchParams.get("state")!, transaction.state) ||
      ((config.requireResponseIssuer !== false ||
        url.searchParams.has("iss")) &&
        (url.searchParams.getAll("iss").length !== 1 ||
          url.searchParams.get("iss") !== config.issuer))
    )
      throw new AuthError("rejected");
    const returnTo = resolveReturnPath(transaction.returnTo);
    let consumed: boolean;
    try {
      consumed = await options.loginStorage.consume(
        await fingerprintAuthValue(transaction.state),
        now(),
      );
    } catch {
      throw new AuthError("unavailable");
    }
    if (!consumed) throw new AuthError("rejected");
    if (
      url.searchParams.has("error") ||
      url.searchParams.getAll("code").length !== 1 ||
      !url.searchParams.get("code")
    )
      throw new AuthError("rejected");
    const code = url.searchParams.get("code")!;
    const key = await keys();
    const token = await tokens(
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: config.redirectUri,
        code_verifier: transaction.verifier,
      }),
      signal,
    );
    if (
      !token.id_token ||
      (config.scopes.includes("offline_access") && !token.refresh_token)
    )
      throw new AuthError("rejected");
    const claims = await verifyIdToken(
      token.id_token,
      token.access_token,
      transaction.nonce,
      key,
      code,
    );
    const credentials: OAuthCredentials = {
      accessToken: token.access_token,
      refreshToken: token.refresh_token,
      accessExpiresAt: now() + token.expires_in * 1000,
      subject: claims.sub!,
      nonce: transaction.nonce,
      refreshExpiresAt: token.refresh_token_expires_in
        ? now() + token.refresh_token_expires_in * 1000
        : undefined,
    };
    try {
      return {
        credentials,
        identity: await identity(credentials, signal),
        sid: claims.sid as string | undefined,
        returnTo,
      };
    } catch (error) {
      await revoke(credentials).catch(() => {});
      throw error;
    }
  }

  async function refresh(
    previous: OAuthCredentials,
    signal?: AbortSignal,
  ): Promise<OAuthCredentials> {
    if (
      !previous.refreshToken ||
      (previous.refreshExpiresAt !== undefined &&
        previous.refreshExpiresAt <= now())
    )
      throw new AuthError("rejected");
    const key = await keys(); // Resolve/cache keys BEFORE consuming a rotating refresh token.
    const token = await tokens(
      new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: previous.refreshToken,
      }),
      signal,
    );
    if (token.id_token) {
      const claims = await verifyIdToken(
        token.id_token,
        token.access_token,
        previous.nonce,
        key,
      );
      if (claims.sub !== previous.subject) throw new AuthError("rejected");
    }
    return {
      ...previous,
      accessToken: token.access_token,
      refreshToken: token.refresh_token ?? previous.refreshToken,
      accessExpiresAt: now() + token.expires_in * 1000,
      refreshExpiresAt: token.refresh_token_expires_in
        ? now() + token.refresh_token_expires_in * 1000
        : previous.refreshExpiresAt,
    };
  }

  async function revoke(credentials: OAuthCredentials, signal?: AbortSignal) {
    const results = await Promise.allSettled(
      [
        [credentials.refreshToken, "refresh_token"],
        [credentials.accessToken, "access_token"],
      ]
        .filter(([token]) => !!token)
        .map(([token, hint]) =>
          request(
            config.endpoints.revocation,
            "POST",
            { "Content-Type": "application/x-www-form-urlencoded" },
            new URLSearchParams({
              client_id: config.clientId,
              token: token!,
              token_type_hint: hint!,
            }),
            signal,
          ),
        ),
    );
    if (results.some((result) => result.status === "rejected"))
      throw new AuthError("unavailable");
  }

  function logoutUrl() {
    const url = new URL(config.endpoints.endSession);
    url.search = new URLSearchParams({
      client_id: config.clientId,
      post_logout_redirect_uri: config.postLogoutRedirectUri,
    }).toString();
    return url.href; // No ID/access/refresh token in navigation URLs.
  }

  return {
    binding,
    startLogin,
    finishLogin,
    identity,
    refresh,
    revoke,
    logoutUrl,
  };
}
