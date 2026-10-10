import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
  base64url,
} from "jose";
import {
  createOAuthProvider,
  validateOAuthConfig,
} from "../src/modules/auth/server/oauth";
import { createLogoutVerifier } from "../src/modules/auth/server/logout";
import { createDesktopLogin } from "../src/modules/auth/desktop";
import { AuthError } from "../src/modules/auth/interface";
import type {
  OAuthConfig,
  VerifiedLogin,
} from "../src/modules/auth/server/interface";
import { deferred, sessionFixture } from "./auth.fixture";

const keyPair = await generateKeyPair("ES256");
const jwk = {
  ...(await exportJWK(keyPair.publicKey)),
  kid: "test",
  alg: "ES256",
};
const keyResolver = createLocalJWKSet({ keys: [jwk] });
const config: OAuthConfig = {
  issuer: "https://sso.example/auth",
  clientId: "test-app",
  redirectUri: "https://app.example/auth/exchange",
  postLogoutRedirectUri: "https://app.example/",
  endpointOrigins: ["https://sso.example"],
  scopes: ["openid", "profile", "email", "offline_access"],
  resources: ["https://api.example", "https://media.example"],
  endpoints: {
    authorization: "https://sso.example/auth/oauth2/authorize",
    token: "https://sso.example/auth/oauth2/token",
    userinfo: "https://sso.example/auth/oauth2/userinfo",
    revocation: "https://sso.example/auth/oauth2/revoke",
    endSession: "https://sso.example/auth/oauth2/end-session",
  },
};

test("local-only OAuth logout needs no end-session configuration", async () => {
  const { endSession: _endSession, ...endpoints } = config.endpoints;
  const { postLogoutRedirectUri: _redirect, ...localConfig } = config;
  const local = { ...localConfig, endpoints };
  assert.doesNotThrow(() => validateOAuthConfig(local));
  const fixture = oauthFixture({ config: local });
  assert.throws(() => fixture.provider.logoutUrl(), {
    code: "invalid_configuration",
  });
  assert.doesNotThrow(() => validateOAuthConfig(config));
  assert.throws(
    () =>
      validateOAuthConfig({
        ...local,
        postLogoutRedirectUri: config.postLogoutRedirectUri,
      }),
    { code: "invalid_configuration" },
  );
});

async function jwt(claims: Record<string, unknown>, type = "JWT") {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "ES256", kid: "test", typ: type })
    .setIssuer(typeof claims.iss === "string" ? claims.iss : config.issuer)
    .setAudience(typeof claims.aud === "string" ? claims.aud : config.clientId)
    .setIssuedAt(typeof claims.iat === "number" ? claims.iat : undefined)
    .setExpirationTime(typeof claims.exp === "number" ? claims.exp : "2m")
    .sign(keyPair.privateKey);
}

function oauthFixture(
  input: {
    config?: OAuthConfig;
    now?: () => number;
    changeClaims?: (claims: Record<string, unknown>) => Record<string, unknown>;
  } = {},
) {
  const receipts = new Map<string, number>();
  let requests = 0;
  let nonce = "";
  let observedBody: URLSearchParams | undefined;
  const provider = createOAuthProvider({
    now: input.now,
    config: input.config ?? config,
    getVerificationKey: async () => keyResolver,
    loginStorage: {
      async reserve(key, expiry) {
        if (receipts.has(key)) return false;
        receipts.set(key, expiry);
        return true;
      },
      async consume(key, now) {
        const expiry = receipts.get(key);
        receipts.delete(key);
        return !!expiry && expiry > now;
      },
    },
    transport: {
      async request(url, options) {
        if (url === config.endpoints.token) {
          requests++;
          observedBody = options.body;
          const claims = {
            sub: "subject-a",
            sid: "sid-a",
            nonce,
            role: "master",
          };
          return {
            status: 200,
            data: {
              token_type: "Bearer",
              access_token: "access",
              refresh_token: "refresh",
              expires_in: 3600,
              id_token: await jwt(input.changeClaims?.(claims) ?? claims),
            },
          };
        }
        if (url === config.endpoints.userinfo)
          return {
            status: 200,
            data: {
              sub: "subject-a",
              name: "Name",
              email: "me@example.com",
              role: "master",
              access_token: "secret",
            },
          };
        return { status: 200, data: {} };
      },
    },
  });
  return {
    provider,
    requests: () => requests,
    body: () => observedBody,
    async start() {
      const start = await provider.startLogin("/settings", "create");
      nonce = start.transaction.nonce;
      const callback = new URL((input.config ?? config).redirectUri);
      callback.search = new URLSearchParams({
        state: start.transaction.state,
        code: "code-a",
        iss: config.issuer,
      }).toString();
      return { ...start, callback };
    },
  };
}

test("PKCE login uses separate random state/nonce, verified identity and resource indicators", async () => {
  const fixture = oauthFixture();
  const { url, transaction, callback } = await fixture.start();
  const authorize = new URL(url);
  assert.equal(authorize.searchParams.get("code_challenge_method"), "S256");
  assert.equal(transaction.state.length, 43);
  assert.notEqual(transaction.state, transaction.nonce);
  assert.equal(authorize.searchParams.get("prompt"), "create");
  assert.deepEqual(authorize.searchParams.getAll("resource"), config.resources);
  const result = await fixture.provider.finishLogin(callback.href, transaction);
  assert.equal(result.identity.subject, "subject-a");
  assert.equal(result.returnTo, "/settings");
  assert.equal("role" in result.identity, false);
  assert.equal("access_token" in result.identity, false);
  assert.equal(fixture.body()?.get("code_verifier"), transaction.verifier);
  assert.deepEqual(fixture.body()?.getAll("resource"), config.resources);
  await assert.rejects(
    fixture.provider.finishLogin(callback.href, transaction),
    { code: "rejected" },
  );
  assert.equal(fixture.requests(), 1);
});

test("OAuth state expires after 120 seconds and cannot exchange an expired code", async () => {
  let now = Date.now();
  const fixture = oauthFixture({ now: () => now });
  const { transaction, callback } = await fixture.start();
  assert.equal(transaction.expiresAt - now, 120_000);
  now += 120_000;
  await assert.rejects(
    fixture.provider.finishLogin(callback.href, transaction),
    { code: "rejected" },
  );
  assert.equal(fixture.requests(), 0);
});

test("callback rejects wrong state/issuer/origin and duplicate parameters before exchange", async () => {
  const mutations = [
    (url: URL) => url.searchParams.set("state", "wrong"),
    (url: URL) => url.searchParams.set("iss", "https://evil.example"),
    (url: URL) => {
      url.hostname = "evil.example";
    },
    (url: URL) =>
      url.searchParams.append("state", url.searchParams.get("state")!),
    (url: URL) => url.searchParams.append("code", "other"),
    (url: URL) => url.searchParams.delete("iss"),
    (url: URL) => url.searchParams.set("error", "access_denied"),
  ];
  for (const mutate of mutations) {
    const fixture = oauthFixture();
    const { callback, transaction } = await fixture.start();
    mutate(callback);
    await assert.rejects(
      fixture.provider.finishLogin(callback.href, transaction),
      { code: "rejected" },
    );
    assert.equal(fixture.requests(), 0);
  }
});

test("ID token rejects nonce, subject and token-hash mismatches", async () => {
  for (const extra of [
    { nonce: "wrong" },
    { sub: "other-subject" },
    { at_hash: "bad-hash" },
    { c_hash: "bad-hash" },
    { azp: "other-client" },
    { iss: "https://wrong.example" },
    { aud: "other-audience" },
    { exp: Math.floor(Date.now() / 1000) - 100 },
    { iat: Math.floor(Date.now() / 1000) + 100 },
  ]) {
    const fixture = oauthFixture({
      changeClaims: (claims) => ({ ...claims, ...extra }),
    });
    const { callback, transaction } = await fixture.start();
    await assert.rejects(
      fixture.provider.finishLogin(callback.href, transaction),
      { code: "rejected" },
    );
  }
});

test("valid at_hash/c_hash verified; refresh subject changes fail closed", async () => {
  const digest = async (value: string) => {
    const bytes = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
    );
    return base64url.encode(bytes.slice(0, bytes.length / 2));
  };
  const at_hash = await digest("access"),
    c_hash = await digest("code-a");
  const fixture = oauthFixture({
    changeClaims: (claims) => ({ ...claims, at_hash, c_hash }),
  });
  const { callback, transaction } = await fixture.start();
  const result = await fixture.provider.finishLogin(callback.href, transaction);
  assert.equal(result.credentials.subject, "subject-a");
  const changed = oauthFixture({
    changeClaims: (claims) => ({
      ...claims,
      sub: "subject-b",
      nonce: undefined,
    }),
  });
  await assert.rejects(changed.provider.refresh(result.credentials), {
    code: "rejected",
  });
});

test("config rejects wildcard/unknown origins, insecure provider and JWT algorithm downgrade", () => {
  for (const override of [
    { endpointOrigins: ["https://*.example"] },
    { issuer: "http://sso.example/auth" },
    { endpoints: { ...config.endpoints, token: "https://evil.example/token" } },
    { redirectUri: "https://app.example/callback?url=evil" },
    { algorithms: ["HS256"] as never },
    { scopes: ["profile"] },
  ])
    assert.throws(() => validateOAuthConfig({ ...config, ...override }));
  const provider = oauthFixture().provider;
  assert.equal(
    new URL(provider.logoutUrl()).searchParams.has("id_token_hint"),
    false,
  );
  assert.equal(
    new URL(provider.logoutUrl()).searchParams.get("post_logout_redirect_uri"),
    config.postLogoutRedirectUri,
  );
});

test("JWKS preparation failure occurs before refresh token rotation", async () => {
  let called = false;
  const provider = createOAuthProvider({
    config,
    getVerificationKey: async () => {
      throw new Error("key outage");
    },
    loginStorage: {
      async reserve() {
        return true;
      },
      async consume() {
        return true;
      },
    },
    transport: {
      async request() {
        called = true;
        return { status: 200, data: {} };
      },
    },
  });
  await assert.rejects(
    provider.refresh({
      subject: "sub",
      nonce: "nonce",
      accessToken: "access",
      refreshToken: "refresh",
      accessExpiresAt: 1,
    }),
    { code: "unavailable" },
  );
  assert.equal(called, false);
});

test("logout verification is signed, typed, issuer/audience-bound and atomic/idempotent", async () => {
  const fixture = sessionFixture();
  const service = fixture.service();
  const { handle } = await service.create(fixture.login);
  const verifier = createLogoutVerifier({
    issuer: config.issuer,
    clientId: config.clientId,
    getVerificationKey: async () => keyResolver,
    storage: fixture.revocation,
  });
  const token = await jwt(
    {
      jti: "logout-a",
      sub: "subject-a",
      sid: "sid-a",
      events: { "http://schemas.openid.net/event/backchannel-logout": {} },
    },
    "logout+jwt",
  );
  const checked = await verifier.verify(token);
  assert.ok(checked.revokeUntil - checked.issuedAt > 6 * 86_400_000);
  assert.equal(
    fixture.records.size,
    1,
    "verify alone must not consume receipt",
  );
  const results = await Promise.all([
    verifier.handle(token),
    verifier.handle(token),
  ]);
  // Cryptographic verification can finish in either order; exactly one wins.
  assert.deepEqual(results.map((result) => result.applied).sort(), [
    false,
    true,
  ]);
  assert.equal(await service.get(handle), null);
});

test("invalid logout token cannot revoke any session", async () => {
  const fixture = sessionFixture();
  const service = fixture.service();
  await service.create(fixture.login);
  const verifier = createLogoutVerifier({
    issuer: config.issuer,
    clientId: config.clientId,
    getVerificationKey: async () => keyResolver,
    storage: fixture.revocation,
  });
  const base = {
    jti: "logout",
    sid: "sid-a",
    events: { "http://schemas.openid.net/event/backchannel-logout": {} },
  };
  for (const claims of [
    { ...base, nonce: "must-not-exist" },
    { ...base, events: {} },
    {
      ...base,
      events: {
        "http://schemas.openid.net/event/backchannel-logout": { invalid: true },
      },
    },
    { ...base, sid: undefined },
    { ...base, jti: "" },
  ]) {
    await assert.rejects(verifier.handle(await jwt(claims, "logout+jwt")), {
      code: "rejected",
    });
  }
  await assert.rejects(verifier.handle(await jwt(base, "JWT")));
  const wrongAudience = createLogoutVerifier({
    issuer: config.issuer,
    clientId: "wrong",
    getVerificationKey: async () => keyResolver,
    storage: fixture.revocation,
  });
  await assert.rejects(wrongAudience.handle(await jwt(base, "logout+jwt")));
  assert.equal(fixture.records.size, 1);
});

test("desktop listener installed before navigation, validates callback, and cleans up", async () => {
  const fixture = oauthFixture({
    config: {
      ...config,
      redirectUri: "http://127.0.0.1:4555/auth/callback",
      allowLoopbackHttp: true,
    },
  });
  let receiver: ((url: string) => boolean) | undefined;
  let closed = 0;
  const provider = {
    ...fixture.provider,
    async startLogin() {
      return fixture.start();
    },
  };
  const desktop = createDesktopLogin({
    provider,
    adapter: {
      listen(receive) {
        receiver = receive;
        return () => {
          receiver = undefined;
        };
      },
      async open(url) {
        assert.ok(receiver);
        const state = new URL(url).searchParams.get("state")!;
        assert.equal(
          receiver("http://127.0.0.1:4555/auth/callback?state=bad"),
          false,
        );
        const callback =
          "http://127.0.0.1:4555/auth/callback?" +
          new URLSearchParams({ state, code: "code-a", iss: config.issuer });
        assert.equal(receiver(callback), true);
        assert.equal(receiver(callback), false);
      },
      async close() {
        closed++;
      },
    },
  });
  const result = await desktop.login();
  assert.equal(result.identity.subject, "subject-a");
  assert.equal(receiver, undefined);
  assert.equal(closed, 1);
});

test("desktop cancellation bounds a hanging open and disposes listener", async () => {
  const fixture = oauthFixture({
    config: {
      ...config,
      redirectUri: "http://127.0.0.1:4555/auth/callback",
      allowLoopbackHttp: true,
    },
  });
  const opened = deferred<void>();
  let listening = false;
  const desktop = createDesktopLogin({
    provider: fixture.provider,
    adapter: {
      listen() {
        listening = true;
        return () => {
          listening = false;
        };
      },
      async open() {
        opened.resolve();
        await new Promise(() => {});
      },
      async close() {},
    },
  });
  const controller = new AbortController();
  const pending = desktop.login({ signal: controller.signal });
  await opened.promise;
  controller.abort();
  await assert.rejects(
    pending,
    (error: unknown) =>
      error instanceof AuthError && error.code === "cancelled",
  );
  assert.equal(listening, false);
});
