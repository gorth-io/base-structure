import { test } from "node:test";
import assert from "node:assert/strict";
import { AuthError } from "../src/modules/auth/interface";
import { createAuthClient } from "../src/modules/auth/client";
import {
  createAuthPolicy,
  assertMutationOrigin,
  authCookieOptions,
  resolveReturnPath,
} from "../src/modules/auth/policy";
import { createAuthCipher } from "../src/modules/auth/server/crypto";
import { createProofReplayStore } from "../src/modules/auth/server/proof";
import { deferred, sessionFixture } from "./auth.fixture";

test("two service instances serialize rotating refresh; only public fields escape", async () => {
  const fixture = sessionFixture();
  const left = fixture.service(),
    right = fixture.service();
  const { handle } = await left.create(fixture.login);
  const result = await Promise.all([
    left.get(handle),
    right.get(handle),
    left.get(handle),
  ]);
  assert.equal(fixture.refreshes(), 1);
  assert.equal(result[0]?.user.role, "editor");
  assert.equal(result[0]?.user.name, "Updated");
  assert.equal(JSON.stringify(result).includes("Token"), false);
  assert.equal(
    fixture.records.has(handle),
    false,
    "store only the hash of a session handle",
  );
});

test("rotation checkpoint survives transient UserInfo failure", async () => {
  const fixture = sessionFixture();
  const service = fixture.service();
  const { handle } = await service.create(fixture.login);
  fixture.provider.identity = async () => {
    throw new AuthError("unavailable");
  };
  await assert.rejects(service.get(handle), { code: "unavailable" });
  assert.equal(
    [...fixture.records.values()][0].credentials.refreshToken,
    "refresh-new",
  );
  fixture.provider.identity = async () => ({ subject: "subject-a" });
  await service.get(handle, { fresh: true });
  assert.equal(fixture.refreshes(), 1);
});

test("local logout wins against in-flight refresh without resurrection", async () => {
  const fixture = sessionFixture();
  const service = fixture.service();
  const started = deferred<void>(),
    continueRefresh = deferred<void>();
  const refresh = fixture.provider.refresh;
  fixture.provider.refresh = async (previous) => {
    started.resolve();
    await continueRefresh.promise;
    return refresh(previous);
  };
  const { handle } = await service.create(fixture.login);
  const request = service.get(handle);
  await started.promise;
  await service.logout(handle);
  continueRefresh.resolve();
  assert.equal(await request, null);
  assert.equal(fixture.records.size, 0);
});

test("backchannel logout fences pending refresh and new sessions on the revoked sid", async () => {
  const fixture = sessionFixture();
  const service = fixture.service();
  const started = deferred<void>(),
    proceed = deferred<void>();
  fixture.provider.refresh = async (previous) => {
    started.resolve();
    await proceed.promise;
    return { ...previous, refreshToken: "rotated" };
  };
  const { handle } = await service.create(fixture.login);
  const request = service.get(handle);
  await started.promise;
  await fixture.revocation.apply({
    jti: "logout",
    sid: "sid-a",
    subject: "subject-a",
    issuedAt: fixture.now(),
    receiptExpiresAt: fixture.now() + 120_000,
    revokeUntil: fixture.now() + 7 * 86_400_000,
  });
  proceed.resolve();
  assert.equal(await request, null);
  await assert.rejects(service.create(fixture.login));
  assert.equal(fixture.records.size, 0);
});

test("inactive local user rejected even within the identity cache window", async () => {
  const fixture = sessionFixture();
  const service = fixture.service();
  const { handle } = await service.create(fixture.login);
  fixture.disable();
  assert.equal(await service.get(handle), null);
  assert.equal(fixture.records.size, 0);
  assert.equal(fixture.refreshes(), 0);
});

test("invalid_grant ends app session; an outage does not", async () => {
  for (const code of ["rejected", "unavailable"] as const) {
    const fixture = sessionFixture();
    const service = fixture.service();
    const { handle } = await service.create(fixture.login);
    fixture.provider.refresh = async () => {
      throw new AuthError(code);
    };
    if (code === "rejected") assert.equal(await service.get(handle), null);
    else await assert.rejects(service.get(handle), { code });
    assert.equal(fixture.records.size, code === "rejected" ? 0 : 1);
  }
});

test("refresh retry occurs once after UserInfo rejection, never loops", async () => {
  const fixture = sessionFixture();
  fixture.login.credentials.accessExpiresAt += 600_000;
  const service = fixture.service();
  const { handle } = await service.create(fixture.login);
  fixture.provider.identity = async () => {
    throw new AuthError("rejected");
  };
  assert.equal(await service.get(handle, { fresh: true }), null);
  assert.equal(fixture.refreshes(), 1);
});

test("expiry, invalid handle, and changed provider binding reject before network", async () => {
  const fixture = sessionFixture();
  const service = fixture.service();
  const { handle } = await service.create(fixture.login);
  assert.equal(await service.get("garbage"), null);
  const session = [...fixture.records.values()][0];
  session.binding = "other-issuer";
  assert.equal(await service.get(handle), null);
  assert.equal(fixture.refreshes(), 0);
  const next = await service.create(fixture.login);
  fixture.advance(8 * 86_400_000);
  assert.equal(await service.get(next.handle), null);
});

test("remote revocation outage never prevents local logout", async () => {
  const fixture = sessionFixture();
  const service = fixture.service();
  const { handle } = await service.create(fixture.login);
  fixture.provider.revoke = async () => {
    throw new AuthError("unavailable");
  };
  assert.deepEqual(await service.logout(handle), { remoteRevoked: false });
  assert.equal(await service.get(handle), null);
});

test("client deduplicates read requests and stale responses cannot undo logout", async () => {
  const pending = deferred<{ user: string; expiresAt: number } | null>();
  let reads = 0;
  const client = createAuthClient<string>({
    async read() {
      reads++;
      return pending.promise;
    },
    async login() {},
    async logout() {},
  });
  const one = client.load(),
    two = client.load();
  assert.equal(one, two);
  await Promise.resolve();
  await client.logout();
  pending.resolve({ user: "old-user", expiresAt: 999 });
  assert.equal(await one, null);
  assert.equal(reads, 1);
  assert.equal(client.getSnapshot().status, "anonymous");
});

test("client loading is not anonymous; sanitized errors; dispose stops stale updates", async () => {
  const pending = deferred<null>();
  const client = createAuthClient({
    async read() {
      return pending.promise;
    },
    async login() {},
    async logout() {},
  });
  assert.equal(client.getSnapshot().status, "loading");
  const read = client.load();
  client.dispose();
  pending.resolve(null);
  await read;
  assert.equal(client.getSnapshot().status, "loading");
  const broken = createAuthClient({
    async read() {
      throw new Error("secret-token");
    },
    async login() {},
    async logout() {},
  });
  await assert.rejects(broken.load(), {
    message: "Authentication unavailable",
  });
  assert.equal(JSON.stringify(broken.getSnapshot()).includes("secret"), false);
});

test("policy bounds, mutation origins, internal redirects and host-only cookies", () => {
  assert.equal(createAuthPolicy().identityMaxAgeMs, 120_000);
  assert.throws(() => createAuthPolicy({ revocationRetentionMs: 120_000 }));
  assert.throws(() => createAuthPolicy({ clockToleranceSeconds: 120 }));
  assert.throws(() => createAuthPolicy({ transactionMaxAgeMs: NaN }));
  assertMutationOrigin(new Headers({ origin: "https://app.example" }), [
    "https://app.example",
  ]);
  for (const headers of [
    new Headers(),
    new Headers({ origin: "https://evil.example" }),
    new Headers({
      origin: "https://app.example",
      "sec-fetch-site": "cross-site",
    }),
  ]) {
    assert.throws(() => assertMutationOrigin(headers, ["https://app.example"]));
  }
  for (const path of [
    "//evil.example",
    "/\\evil.example",
    "https://evil.example",
    "/\n/evil",
  ])
    assert.throws(() => resolveReturnPath(path));
  assert.equal(resolveReturnPath("/settings?mode=dark"), "/settings?mode=dark");
  assert.deepEqual(authCookieOptions({ secure: true, maxAgeSeconds: 0 }), {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
});

test("cipher is purpose/audience/key bound and rejects expired/tampered ciphertext", async () => {
  let time = Date.now();
  const key = crypto.getRandomValues(new Uint8Array(32));
  const cipher = createAuthCipher({ key, audience: "app-a", now: () => time });
  const sealed = await cipher.seal(
    { token: "private" },
    "credentials",
    time + 2000,
  );
  assert.deepEqual(await cipher.open(sealed, "credentials"), {
    token: "private",
  });
  await assert.rejects(cipher.open(sealed, "transaction"));
  await assert.rejects(
    createAuthCipher({ key, audience: "app-b" }).open(sealed, "credentials"),
  );
  await assert.rejects(
    cipher.open(sealed.slice(0, -5) + "aaaaa", "credentials"),
  );
  time += 3000;
  await assert.rejects(cipher.open(sealed, "credentials"));
});

test("DPoP adapter matches Better Auth reserve contract and shares atomic storage", async () => {
  const consumed = new Set<string>();
  const adapter = {
    async consume(key: string) {
      if (consumed.has(key)) return false;
      consumed.add(key);
      return true;
    },
  };
  const a = createProofReplayStore(adapter),
    b = createProofReplayStore(adapter);
  const request = {
    key: "key:thumbprint:jti",
    now: new Date(),
    expiresAt: new Date(Date.now() + 60_000),
  };
  assert.deepEqual(
    await Promise.all([a.reserve(request), b.reserve(request)]),
    [true, false],
  );
  await assert.rejects(
    Promise.resolve(a.reserve({ ...request, expiresAt: new Date(0) })),
  );
});
