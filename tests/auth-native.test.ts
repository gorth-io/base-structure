import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AuthError,
  createIdentityCache,
  createOAuthIdentityValidator,
  createSessionGrantGuard,
  matchesAuthRevocation,
} from "../src/modules/auth/server";
import { deferred } from "./auth.fixture";

test("forget fences pending key derivation without invalidating other identities", async () => {
  const key = deferred<string>();
  let calls = 0;
  const cache = createIdentityCache({
    key: async (credential) =>
      credential === "token" && ++calls === 1 ? await key.promise : credential,
    load: async (credential) => credential,
  });
  const old = cache.get("token");
  const other = cache.get("other");
  await cache.forget("token");
  key.resolve("token");
  await assert.rejects(old, { code: "rejected" });
  assert.equal(await other, "other");
  assert.equal(await cache.get("token"), "token");
});

test("cache does not extend freshness by network duration or retain failed/invalidated flights", async () => {
  let time = 0,
    calls = 0;
  const cache = createIdentityCache({
    now: () => time,
    maxAgeMs: 10,
    load: async () => {
      calls++;
      time += 11;
      return "profile";
    },
  });
  await cache.get("token");
  await cache.get("token");
  assert.equal(calls, 2);
  const pending = deferred<string>();
  const invalidated = createIdentityCache({ load: () => pending.promise });
  const request = invalidated.get("token");
  await Promise.resolve();
  await Promise.resolve();
  invalidated.clear();
  pending.resolve("old");
  await assert.rejects(request, { code: "rejected" });
});

test("identity cache coalesces checks, respects TTL/freshness and keeps keys hashed", async () => {
  let time = 0,
    calls = 0;
  const cache = createIdentityCache({
    now: () => time,
    maxAgeMs: 120,
    async load() {
      calls++;
      return Object.freeze({ sub: "subject", sequence: calls });
    },
  });
  const [first, second] = await Promise.all([
    cache.get("token"),
    cache.get("token"),
  ]);
  assert.equal(first, second);
  assert.equal(calls, 1);
  time = 119;
  assert.equal(await cache.get("token"), first);
  time = 120;
  assert.equal((await cache.get("token")).sequence, 2);
  assert.equal((await cache.get("token", { fresh: true })).sequence, 3);
  await cache.forget("token");
  assert.equal((await cache.get("token")).sequence, 4);
});

test("logout invalidation fences a pending profile and permits a new check", async () => {
  const old = deferred<string>();
  let calls = 0;
  const cache = createIdentityCache({
    key: async (value) => value,
    load: async () => (++calls === 1 ? await old.promise : "new"),
  });
  const first = cache.get("key");
  await Promise.resolve();
  await Promise.resolve();
  await cache.forget("key");
  assert.equal(await cache.get("key"), "new");
  old.resolve("old");
  await assert.rejects(first, { code: "rejected" });
  assert.equal(await cache.get("key"), "new");
});

test("clear fences pending key derivation and no expired/outage fallback is served", async () => {
  const key = deferred<string>();
  const cache = createIdentityCache({
    key: () => key.promise,
    load: async () => "stale",
  });
  const request = cache.get("credential");
  cache.clear();
  key.resolve("key");
  await assert.rejects(request, { code: "rejected" });
  let time = 0,
    fail = false;
  const available = createIdentityCache({
    maxAgeMs: 1,
    now: () => time,
    load: async () => {
      if (fail) throw new Error("SECRET");
      return "identity";
    },
  });
  await available.get("token");
  time = 2;
  fail = true;
  await assert.rejects(available.get("token"), (error) => {
    assert.equal((error as Error).message, "Authentication unavailable");
    return true;
  });
});

test("bounded cache eviction and pending capacity do not evict an active flight", async () => {
  let calls = 0;
  const cache = createIdentityCache({
    capacity: 1,
    load: async (token) => {
      calls++;
      return token;
    },
  });
  await cache.get("a");
  await cache.get("b");
  await cache.get("a");
  assert.equal(calls, 3);
  const pending = deferred<string>();
  const busy = createIdentityCache({
    maxPending: 1,
    key: async (value) => value,
    load: () => pending.promise,
  });
  const first = busy.get("one");
  await Promise.resolve();
  await Promise.resolve();
  await assert.rejects(busy.get("two"), { code: "unavailable" });
  pending.resolve("one");
  assert.equal(await first, "one");
  for (const options of [
    { capacity: 0 },
    { maxAgeMs: NaN },
    { maxPending: -1 },
  ])
    assert.throws(
      () => createIdentityCache({ ...options, load: async () => null }),
      AuthError,
    );
});

test("cancelling a cache waiter does not abort a shared check", async () => {
  const pending = deferred<string>();
  const cache = createIdentityCache({ load: () => pending.promise });
  const controller = new AbortController();
  const first = cache.get("credential", { signal: controller.signal });
  const other = cache.get("credential");
  await Promise.resolve();
  await Promise.resolve();
  controller.abort();
  await assert.rejects(first, { name: "AbortError" });
  pending.resolve("identity");
  assert.equal(await other, "identity");
});

test("native identity validator binds OAuth provider/sub without trusting email or role", async () => {
  const validator = createOAuthIdentityValidator({
    providerId: "tenant",
    subject: (user) => (user as { externalUserId?: string }).externalUserId,
    allowed: (profile) => profile.status === "active",
  });
  const input = {
    user: {
      id: "local-id",
      externalUserId: "central-sub",
      email: "same@example.test",
    },
    source: {
      method: "oauth",
      oauth: {
        providerId: "tenant",
        profile: { sub: "central-sub", status: "active", role: "admin" },
      },
    },
  };
  const check = async (value: unknown) =>
    await validator(
      value as Parameters<typeof validator>[0],
      undefined as never,
    );
  assert.equal(await check(input), undefined);
  assert.deepEqual(await check({ ...input, source: { method: "email" } }), {
    error: "invalid_identity_source",
  });
  assert.deepEqual(
    await check({ ...input, user: { ...input.user, externalUserId: "other" } }),
    { error: "invalid_identity_source" },
  );
  assert.deepEqual(
    await check({
      ...input,
      source: {
        method: "oauth",
        oauth: { ...input.source.oauth, providerId: "other" },
      },
    }),
    { error: "invalid_identity_source" },
  );
  input.source.oauth.profile.status = "inactive";
  assert.deepEqual(await check(input), { error: "account_unavailable" });
});

test("session grant guard validates before/after SDK refresh and rejects logout/account changes", async () => {
  const initial = {
    id: "session",
    userId: "local",
    subject: "sso",
    sid: "sid",
    expiresAt: 100,
  };
  let current: typeof initial | null = initial,
    allowed = true,
    checks = 0;
  const guard = createSessionGrantGuard({
    now: () => 1,
    read: async () => current,
    assertAllowed: async () => {
      checks++;
      if (!allowed) throw new AuthError("forbidden");
    },
  });
  assert.equal(await guard.run(async () => "token"), "token");
  assert.equal(checks, 2);
  await assert.rejects(
    guard.run(async () => {
      current = null;
      return "stale-token";
    }),
    { code: "rejected" },
  );
  current = initial;
  await assert.rejects(
    guard.run(async () => {
      current = { ...initial, sid: "other" };
      return "wrong-account";
    }),
    { code: "rejected" },
  );
  current = initial;
  await assert.rejects(
    guard.run(async () => {
      allowed = false;
      return "blocked";
    }),
    { code: "forbidden" },
  );
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    guard.run(async () => "cancelled", controller.signal),
    { code: "cancelled" },
  );
});

test("revocation requires both identifiers; subject-only cutoffs cover exactly the issuance second", () => {
  const marker = {
    subject: "sub",
    sid: "sid",
    issuedAt: 1500,
    expiresAt: 10000,
  };
  const identity = { subject: "sub", sid: "sid", issuedAt: 5000 };
  assert.equal(matchesAuthRevocation(marker, identity, 9000), true);
  assert.equal(
    matchesAuthRevocation(marker, { ...identity, subject: "other" }, 9000),
    false,
  );
  assert.equal(
    matchesAuthRevocation(marker, { ...identity, sid: "other" }, 9000),
    false,
  );
  assert.equal(matchesAuthRevocation(marker, identity, 10000), false);
  assert.equal(
    matchesAuthRevocation(
      { ...marker, sid: undefined },
      { ...identity, issuedAt: 1999 },
      9000,
    ),
    true,
  );
  assert.equal(
    matchesAuthRevocation(
      { ...marker, sid: undefined },
      { ...identity, issuedAt: 2000 },
      9000,
    ),
    false,
  );
  assert.throws(
    () =>
      matchesAuthRevocation(
        { ...marker, subject: undefined, sid: undefined },
        identity,
      ),
    AuthError,
  );
});
