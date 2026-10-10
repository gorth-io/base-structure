import { test } from "node:test";
import assert from "node:assert/strict";
import { createAuthRetry } from "../src/modules/auth/client";
import { deferred } from "./auth.fixture";

test("retry deduplicates refresh and never retries a second 401", async () => {
  let refreshes = 0,
    requests = 0;
  const pending = deferred<boolean>();
  const retry = createAuthRetry({
    getStatus: () => 401,
    refresh: async () => {
      refreshes++;
      return pending.promise;
    },
  });
  const request = async () => {
    requests++;
    throw new Error("unauthorized");
  };
  const first = retry.withAuthRetry(request);
  const second = retry.withAuthRetry(request);
  await Promise.resolve();
  await Promise.resolve();
  pending.resolve(true);
  await Promise.all([
    assert.rejects(first, /unauthorized/),
    assert.rejects(second, /unauthorized/),
  ]);
  assert.equal(refreshes, 1);
  assert.equal(requests, 4);
});

test("aborted waiter does not cancel another request's shared refresh", async () => {
  const pending = deferred<boolean>();
  const controller = new AbortController();
  let allowed = false,
    sharedSignal!: AbortSignal;
  const retry = createAuthRetry({
    getStatus: () => 401,
    refresh: async (signal) => {
      sharedSignal = signal;
      return pending.promise;
    },
  });
  const request = async () => {
    if (!allowed) throw new Error("401");
    return "ok";
  };
  const first = retry.withAuthRetry(request, { signal: controller.signal });
  const second = retry.withAuthRetry(request);
  await Promise.resolve();
  await Promise.resolve();
  controller.abort();
  await assert.rejects(first, { name: "AbortError" });
  assert.equal(sharedSignal.aborted, false);
  allowed = true;
  pending.resolve(true);
  assert.equal(await second, "ok");
});

test("logout reset invalidates refresh completion; failed refresh preserves original error", async () => {
  const pending = deferred<boolean>();
  let requests = 0;
  const failure = new Error("original");
  const retry = createAuthRetry({
    getStatus: () => 401,
    refresh: () => pending.promise,
  });
  const operation = retry.withAuthRetry(async () => {
    requests++;
    throw failure;
  });
  await Promise.resolve();
  await Promise.resolve();
  retry.reset();
  pending.resolve(true);
  await assert.rejects(operation, (error) => error === failure);
  assert.equal(requests, 1);
  const unavailable = createAuthRetry({
    getStatus: () => 401,
    refresh: async () => {
      throw new Error("outage");
    },
  });
  await assert.rejects(
    unavailable.withAuthRetry(async () => {
      throw failure;
    }),
    (error) => error === failure,
  );
});

test("non-401, disabled and disposed retries do not refresh", async () => {
  let refreshes = 0;
  const retry = createAuthRetry({
    getStatus: () => 403,
    refresh: async () => {
      refreshes++;
      return true;
    },
  });
  const failure = async () => {
    throw new Error("denied");
  };
  await assert.rejects(retry.withAuthRetry(failure));
  await assert.rejects(retry.withAuthRetry(failure, { enabled: false }));
  retry.dispose();
  await assert.rejects(retry.withAuthRetry(failure));
  assert.equal(refreshes, 0);
});
