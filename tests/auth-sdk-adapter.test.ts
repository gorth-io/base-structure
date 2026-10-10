import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createAuthClient,
  createSessionAuthAdapter,
} from "../src/modules/auth/client";
import { deferred } from "./auth.fixture";

function fixture() {
  const native = {
    user: { id: "user-1", name: "Name", privateKey: "SECRET" },
    session: { token: "SECRET-SESSION", expiresAt: new Date(120_000) },
  };
  let loggedOut = false;
  const adapter = createSessionAuthAdapter({
    getSession: async () => ({ data: loggedOut ? null : native, error: null }),
    signOut: async () => {
      loggedOut = true;
      return { data: { success: true }, error: null };
    },
    mapUser: (user) => ({ id: user.id, name: user.name }),
    login: async () => {
      loggedOut = false;
    },
    now: () => 1_000,
  });
  return { adapter, native };
}

test("SDK session adapter projects public fields and supports client store login/logout", async () => {
  const { adapter } = fixture();
  const client = createAuthClient(adapter);
  assert.deepEqual(await client.load(), {
    user: { id: "user-1", name: "Name" },
    expiresAt: 120_000,
  });
  assert(!JSON.stringify(client.getSnapshot()).includes("SECRET"));
  await client.logout();
  assert.equal(await client.load(), null);
  await client.login();
  assert.equal(client.getSnapshot().status, "authenticated");
  client.dispose();
});

test("SDK session adapter accepts ISO expiry and rejects invalid/expired snapshots", async () => {
  for (const [expiresAt, expected] of [
    [new Date(120_000).toISOString(), 120_000],
    [120_000, 120_000],
    [1_000, null],
  ] as const) {
    const adapter = createSessionAuthAdapter({
      getSession: async () => ({
        data: { user: "public", session: { expiresAt } },
      }),
      signOut: async () => ({ data: null }),
      login: async () => {},
      mapUser: (user) => user,
      now: () => 1_000,
    });
    assert.equal(
      (await adapter.read(new AbortController().signal))?.expiresAt ?? null,
      expected,
    );
  }
  const adapter = createSessionAuthAdapter({
    getSession: async () => ({
      data: { user: "public", session: { expiresAt: "bad" } },
    }),
    signOut: async () => ({ data: null }),
    login: async () => {},
    mapUser: (user) => user,
  });
  await assert.rejects(adapter.read(new AbortController().signal), {
    code: "rejected",
  });
});

test("SDK errors never become public credentials or a successful logout", async () => {
  const error = { message: "SECRET-TOKEN", code: "UPSTREAM" };
  const adapter = createSessionAuthAdapter({
    getSession: async () => ({ data: null, error }),
    signOut: async () => ({ data: null, error }),
    login: async () => {
      throw error;
    },
    mapUser: () => ({ id: "public" }),
    errorCode: () => "forbidden",
  });
  for (const operation of [adapter.read, adapter.logout])
    await assert.rejects(
      operation(new AbortController().signal),
      (value: unknown) => {
        assert.equal((value as Error).message, "Authentication forbidden");
        assert(!JSON.stringify(value).includes("SECRET"));
        return true;
      },
    );
});

test("SDK session adapter fences cancellation even when SDK ignores abort", async () => {
  const wait = deferred<{ data: null }>();
  const adapter = createSessionAuthAdapter({
    getSession: () => wait.promise,
    signOut: async () => ({ data: null }),
    login: async () => {},
    mapUser: () => null,
  });
  const controller = new AbortController();
  const read = adapter.read(controller.signal);
  controller.abort();
  wait.resolve({ data: null });
  await assert.rejects(read, { code: "cancelled" });
});
