import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
  jwtVerify,
} from "jose";
import { createHmac, createHash } from "node:crypto";
import {
  createSessionBoundTransport,
  createOidcDiscovery,
  createBffSigner,
  createBffVerifier,
} from "../src/modules/auth/server";
import type { AuthTransport } from "../src/modules/auth/server";
import { deferred, sessionFixture } from "./auth.fixture";

const pair = await generateKeyPair("ES256");
const jwk = { ...(await exportJWK(pair.publicKey)), kid: "one", alg: "ES256" };
const keys = { keys: [jwk] };
const resolver = createLocalJWKSet(keys);
const issuer = "https://sso.example/auth";
const tokenUrl = issuer + "/oauth2/token",
  revocationUrl = issuer + "/oauth2/revoke";
async function signed(claims: Record<string, unknown> = {}) {
  return new SignJWT({ sid: "sid-a", ...claims })
    .setProtectedHeader({ alg: "ES256", kid: "one" })
    .setIssuer(issuer)
    .setAudience("app")
    .setSubject("subject-a")
    .setIssuedAt()
    .setExpirationTime("2m")
    .sign(pair.privateKey);
}

test("session-bound transport accepts signed sid and rejects detached grant, revoking its refresh token", async () => {
  let idToken = await signed();
  const calls: { url: string; body?: URLSearchParams }[] = [];
  const transport: AuthTransport = {
    async request(url, input) {
      calls.push({ url, body: input.body });
      return {
        status: 200,
        data: { id_token: idToken, refresh_token: "new-refresh" },
      };
    },
  };
  const bound = createSessionBoundTransport(transport, {
    issuer,
    clientId: "app",
    tokenUrl,
    revocationUrl,
    endpointOrigins: ["https://sso.example"],
    key: () => resolver,
  });
  const input = { method: "POST" as const, headers: {} };
  assert.equal((await bound.request(tokenUrl, input)).status, 200);
  idToken = await signed({ sid: undefined });
  await assert.rejects(bound.request(tokenUrl, input), { code: "rejected" });
  assert.equal(calls.at(-1)?.url, revocationUrl);
  assert.equal(calls.at(-1)?.body?.get("token"), "new-refresh");
  assert.equal((await bound.request(issuer + "/userinfo", input)).status, 200);
});

test("session binding pins prepared keys across concurrent cache invalidation", async () => {
  const token = await signed();
  let current: typeof resolver | undefined = resolver;
  const bound = createSessionBoundTransport(
    {
      async request() {
        current = undefined;
        return { status: 200, data: { id_token: token } };
      },
    },
    {
      issuer,
      clientId: "app",
      tokenUrl,
      revocationUrl,
      endpointOrigins: ["https://sso.example"],
      key: () => current,
    },
  );
  assert.equal(
    (await bound.request(tokenUrl, { method: "POST", headers: {} })).status,
    200,
  );
});

test("session binding checks audience and preloaded keys; unavailable revoke does not undo denial", async () => {
  const token = await signed();
  const transport: AuthTransport = {
    async request() {
      return {
        status: 200,
        data: { id_token: token, refresh_token: "new-refresh" },
      };
    },
  };
  let revokes = 0;
  for (const [clientId, key] of [
    ["wrong", () => resolver],
    ["app", () => undefined],
  ] as const) {
    const bound = createSessionBoundTransport(transport, {
      issuer,
      clientId,
      tokenUrl,
      revocationUrl,
      endpointOrigins: ["https://sso.example"],
      key,
      async revokeRejectedGrant() {
        revokes++;
        throw new Error("outage");
      },
    });
    await assert.rejects(
      bound.request(tokenUrl, { method: "POST", headers: {} }),
      { code: "rejected" },
    );
  }
  assert.equal(revokes, 2);
  assert.throws(
    () =>
      createSessionBoundTransport(transport, {
        issuer,
        clientId: "app",
        tokenUrl,
        revocationUrl: "https://evil.example/revoke",
        endpointOrigins: ["https://sso.example"],
        key: () => resolver,
      }),
    { code: "invalid_configuration" },
  );
});

test("discovery validates metadata/JWKS, deduplicates requests, caches and explicitly rotates keys", async () => {
  let calls = 0,
    now = Date.now();
  const discovery = createOidcDiscovery({
    issuer,
    endpointOrigins: ["https://sso.example"],
    allowedPath: (url) => url.pathname.startsWith("/auth/"),
    now: () => now,
    transport: {
      async request(url) {
        calls++;
        return {
          status: 200,
          data: url.endsWith("openid-configuration")
            ? { issuer, jwks_uri: issuer + "/jwks", token_endpoint: tokenUrl }
            : keys,
        };
      },
    },
  });
  assert.equal(discovery.currentVerificationKey(), undefined);
  const [one, two] = await Promise.all([
    discovery.getVerificationKey(),
    discovery.getVerificationKey(),
  ]);
  assert.equal(one, two);
  assert.equal(calls, 2);
  assert.equal((await jwtVerify(await signed(), one)).payload.sid, "sid-a");
  await discovery.metadata();
  assert.equal(calls, 2);
  now += 300_001;
  await discovery.getVerificationKey();
  assert.equal(calls, 4);
  await discovery.getVerificationKey({ force: true });
  assert.equal(calls, 6);
  discovery.invalidate();
  assert.equal(discovery.currentVerificationKey(), undefined);
});

test("discovery rejects wrong issuer, foreign/query JWKS, private keys and never returns expired fallback on outage", async () => {
  for (const metadata of [
    { issuer: "https://evil.example", jwks_uri: issuer + "/jwks" },
    { issuer, jwks_uri: "https://evil.example/jwks" },
    { issuer, jwks_uri: issuer + "/jwks?token=secret" },
  ]) {
    let calls = 0;
    const discovery = createOidcDiscovery({
      issuer,
      endpointOrigins: ["https://sso.example"],
      transport: {
        async request() {
          calls++;
          return { status: 200, data: metadata };
        },
      },
    });
    await assert.rejects(discovery.getVerificationKey(), { code: "rejected" });
    assert.equal(calls, 1);
  }
  let now = Date.now(),
    unavailable = false;
  const discovery = createOidcDiscovery({
    issuer,
    endpointOrigins: ["https://sso.example"],
    cacheMaxAgeMs: 1,
    now: () => now,
    transport: {
      async request(url) {
        if (unavailable) throw new Error("network secret");
        return {
          status: 200,
          data: url.endsWith("openid-configuration")
            ? { issuer, jwks_uri: issuer + "/jwks" }
            : keys,
        };
      },
    },
  });
  await discovery.getVerificationKey();
  now += 2;
  unavailable = true;
  await assert.rejects(discovery.getVerificationKey(), {
    code: "unavailable",
    message: "Authentication unavailable",
  });
  const privateKeys = createOidcDiscovery({
    issuer,
    endpointOrigins: ["https://sso.example"],
    transport: {
      async request(url) {
        return {
          status: 200,
          data: url.endsWith("openid-configuration")
            ? { issuer, jwks_uri: issuer + "/jwks" }
            : { keys: [{ ...jwk, d: "private" }] },
        };
      },
    },
  });
  await assert.rejects(privateKeys.getVerificationKey(), { code: "rejected" });
});

test("discovery aborted waiter and invalidated flight cannot publish stale keys", async () => {
  const pending = deferred<{ status: number; data: unknown }>();
  const discovery = createOidcDiscovery({
    issuer,
    endpointOrigins: ["https://sso.example"],
    transport: {
      async request(url) {
        return url.endsWith("openid-configuration")
          ? pending.promise
          : { status: 200, data: keys };
      },
    },
  });
  const controller = new AbortController();
  const first = discovery.getVerificationKey({ signal: controller.signal });
  const second = discovery.getVerificationKey();
  controller.abort();
  await assert.rejects(first, { name: "AbortError" });
  discovery.invalidate();
  pending.resolve({
    status: 200,
    data: { issuer, jwks_uri: issuer + "/jwks" },
  });
  await assert.rejects(second, { code: "cancelled" });
  assert.equal(discovery.currentVerificationKey(), undefined);
});

test("server credentials share refresh/local policy and never appear in public session", async () => {
  const fixture = sessionFixture();
  const service = fixture.service();
  const { handle } = await service.create(fixture.login);
  const [credentials, session] = await Promise.all([
    service.credentials(handle),
    service.get(handle),
  ]);
  assert.equal(fixture.refreshes(), 1);
  assert.equal(credentials?.credentials.accessToken, "access-new");
  assert.equal(credentials?.subject, "subject-a");
  assert.equal(JSON.stringify(session).includes("access-new"), false);
  fixture.disable();
  assert.equal(await service.credentials(handle), null);
});

test("credentials enforce authoritative revocation and local logout permits new login on same SSO sid", async () => {
  const fixture = sessionFixture();
  const service = fixture.service();
  const first = await service.create(fixture.login);
  await service.logout(first.handle);
  assert.equal(await service.credentials(first.handle), null);
  const second = await service.create(fixture.login);
  assert.ok(await service.credentials(second.handle));
  await fixture.revocation.apply({
    jti: "logout",
    sid: "sid-a",
    issuedAt: fixture.now(),
    receiptExpiresAt: fixture.now() + 120_000,
    revokeUntil: fixture.now() + 7 * 86_400_000,
  });
  assert.equal(await service.credentials(second.handle), null);
});

function bffFixture() {
  let now = Date.now();
  const key = new Uint8Array(32).fill(7);
  const records = new Map<string, number>();
  const options = {
    context: "gorth-chat-bff-v1",
    key: () => key,
    now: () => now,
  };
  const signer = createBffSigner(options);
  const verify = createBffVerifier({
    ...options,
    proof: {
      async consume(key, expiry) {
        if ((records.get(key) ?? 0) > now) return false;
        records.set(key, expiry);
        return true;
      },
    },
  });
  return {
    signer,
    verify,
    key,
    now: () => now,
    records,
    advance(ms: number) {
      now += ms;
    },
  };
}

test("BFF wire signature matches existing HMAC contract; replay rejected atomically", async () => {
  const fixture = bffFixture(),
    body = '{"action":"read"}',
    path = "/internal/auth/read";
  const headers = await fixture.signer(path, body);
  const expected = createHmac("sha256", fixture.key)
    .update(
      [
        "gorth-chat-bff-v1",
        "POST",
        path,
        headers["x-bff-time"],
        headers["x-bff-nonce"],
        createHash("sha256").update(body).digest("hex"),
      ].join("\n"),
    )
    .digest("hex");
  assert.equal(headers["x-bff-signature"], expected);
  const legacyProofKey =
    "bff:" + createHash("sha256").update(headers["x-bff-nonce"]).digest("hex");
  const request = () =>
    new Request("https://api.example" + path, { method: "POST", headers });
  await fixture.verify(request(), body);
  await assert.rejects(fixture.verify(request(), body), { code: "rejected" });
  assert.equal(fixture.records.size, 1);
  assert.ok(fixture.records.has(legacyProofKey));
});

test("BFF binds method, exact path/query, body, namespace and time; invalid signatures consume no proof", async () => {
  const fixture = bffFixture(),
    body = "{}",
    path = "/internal/auth/read?resource=one";
  const headers = await fixture.signer(path, body);
  for (const [method, target, payload] of [
    ["GET", path, body],
    ["POST", "/internal/auth/write", body],
    ["POST", "/internal/auth/read?resource=two", body],
    ["POST", path, "changed"],
  ]) {
    await assert.rejects(
      fixture.verify(
        new Request("https://api.example" + target, { method, headers }),
        payload,
      ),
      { code: "rejected" },
    );
  }
  const foreign = await createBffSigner({
    context: "another-protocol",
    key: () => fixture.key,
  })(path, body);
  await assert.rejects(
    fixture.verify(
      new Request("https://api.example" + path, {
        method: "POST",
        headers: foreign,
      }),
      body,
    ),
    { code: "rejected" },
  );
  fixture.advance(30_001);
  await assert.rejects(
    fixture.verify(
      new Request("https://api.example" + path, { method: "POST", headers }),
      body,
    ),
    { code: "rejected" },
  );
  assert.equal(fixture.records.size, 0);
});

test("BFF bounds payload/key and sanitized storage errors; future timestamp replay lifetime is covered", async () => {
  await assert.rejects(
    createBffSigner({ context: "bff", key: () => new Uint8Array(1) })(
      "/internal/auth",
      "{}",
    ),
    { code: "invalid_configuration" },
  );
  await assert.rejects(
    createBffSigner({
      context: "bff",
      key: () => new Uint8Array(32),
      maxBodyBytes: 1,
    })("/internal/auth", "{}"),
    { code: "rejected" },
  );
  const fixture = bffFixture();
  const headers = await fixture.signer("/internal/auth", "{}");
  const request = new Request("https://api.example/internal/auth", {
    method: "POST",
    headers,
  });
  const outage = createBffVerifier({
    context: "gorth-chat-bff-v1",
    key: () => fixture.key,
    now: fixture.now,
    proof: {
      async consume() {
        throw new Error("private DB URL");
      },
    },
  });
  await assert.rejects(outage(request, "{}"), {
    code: "unavailable",
    message: "Authentication unavailable",
  });
  fixture.advance(-30_000);
  await fixture.verify(request, "{}");
  const proofExpiry = [...fixture.records.values()][0];
  assert.ok(proofExpiry > Number(headers["x-bff-time"]) + 30_000);
});
