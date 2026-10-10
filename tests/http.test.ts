import { test } from "node:test";
import assert from "node:assert/strict";
import axios, {
  AxiosError,
  AxiosHeaders,
  type AxiosResponse,
  type InternalAxiosRequestConfig,
} from "axios";
import { z } from "zod";
import {
  createFetcher,
  createCaller,
  toWebResponse,
  CallerError,
  normalizeCallerError,
} from "../src/modules/http";

function response(
  config: InternalAxiosRequestConfig,
  data: unknown,
  status = 200,
): AxiosResponse {
  return {
    config,
    data,
    status,
    statusText: "OK",
    headers: new AxiosHeaders({ "content-type": "application/json" }),
  };
}

test("fetcher keeps injected adapter/defaults, cache headers, body and cancellation", async () => {
  const controller = new AbortController();
  let observed!: InternalAxiosRequestConfig;
  const client = axios.create({
    withCredentials: true,
    adapter: async (config) => {
      observed = config;
      return response(config, { ok: true });
    },
  });
  const fetcher = createFetcher(client);
  await fetcher({
    url: new URL("https://example.test/item"),
    method: "POST",
    body: { value: 1 },
    cache: "no-store",
    redirect: "manual",
    signal: controller.signal,
  });
  assert.equal(observed.maxRedirects, 0);
  assert.equal(observed.withCredentials, true);
  assert.equal(observed.signal, controller.signal);
  assert.equal(observed.headers.get("cache-control"), "no-store");
  assert.equal(observed.data, '{"value":1}');
  await fetcher({
    url: "https://example.test/item",
    method: "GET",
    credentials: "omit",
  });
  assert.equal(observed.withCredentials, false);
  const sharedHeaders = new AxiosHeaders({ Accept: "application/json" });
  await fetcher({
    url: "https://example.test/item",
    method: "GET",
    headers: sharedHeaders,
    cache: "no-store",
  });
  assert.equal(
    sharedHeaders.has("cache-control"),
    false,
    "request must not mutate app-owned headers",
  );
});

test("redirect:error rejects 3xx even with permissive validateStatus", async () => {
  const fetcher = createFetcher(
    axios.create({ adapter: async (config) => response(config, "", 302) }),
  );
  await assert.rejects(
    fetcher({
      url: "https://example.test",
      method: "GET",
      redirect: "error",
      validateStatus: () => true,
    }),
    /Redirect refused/,
  );
});

test("web response preserves JSON null and individual Set-Cookie; removes stale wire headers", async () => {
  const source: AxiosResponse = {
    config: {} as InternalAxiosRequestConfig,
    status: 200,
    statusText: "OK",
    data: null,
    headers: {
      "content-type": "application/json",
      "set-cookie": ["one=1; HttpOnly", "two=2; HttpOnly"],
      "content-length": "42",
      "content-encoding": "gzip",
      connection: "x-hop",
      "x-hop": "remove-me",
    },
  };
  const result = toWebResponse(source);
  assert.equal(await result.text(), "null");
  assert.deepEqual(result.headers.getSetCookie(), source.headers["set-cookie"]);
  assert.equal(result.headers.has("content-encoding"), false);
  assert.equal(result.headers.has("content-length"), false);
  assert.equal(result.headers.has("x-hop"), false);
  assert.equal(await toWebResponse(source, { emptyBody: true }).text(), "");
  for (const status of [204, 205, 304])
    assert.equal(
      toWebResponse({ ...source, status, data: { ignored: true } }).body,
      null,
    );
});

test("web response preserves redirects and exact typed-array slice", async () => {
  const source: AxiosResponse = {
    config: {} as InternalAxiosRequestConfig,
    status: 302,
    statusText: "Found",
    data: new Uint8Array([1, 2, 3, 4]).subarray(1, 3),
    headers: { location: "/next" },
  };
  const result = toWebResponse(source);
  assert.deepEqual(
    new Uint8Array(await result.arrayBuffer()),
    new Uint8Array([2, 3]),
  );
  assert.equal(result.headers.get("location"), "/next");
});

test("caller unwraps and validates data, injects notifications, preserves custom response handlers", async () => {
  const notices: string[] = [];
  const client = axios.create({
    adapter: async (config) => response(config, { data: { count: 3 } }),
  });
  const api = createCaller({
    client,
    notify: (kind, message) => notices.push(kind + ":" + message),
  });
  const result = await api.http.get("/item", {
    schema: z.object({ count: z.number() }),
    toast: { success: (value) => String(value.count) },
  });
  assert.deepEqual(result, { count: 3 });
  assert.deepEqual(notices, ["success:3"]);
  assert.equal(
    await api.caller({
      url: "/item",
      responseHandler: (result) => result.status,
    }),
    200,
  );
  await assert.rejects(
    api.caller({ url: "/item", schema: z.string(), toast: false }),
    CallerError,
  );
});

test("caller refreshes once for concurrent reads; mutations and auth routes do not replay implicitly", async () => {
  let authenticated = false,
    refreshes = 0,
    requests = 0;
  const client = axios.create({
    adapter: async (config) => {
      requests++;
      if (!authenticated)
        throw new AxiosError(
          "bad",
          "ERR_BAD_REQUEST",
          config,
          undefined,
          response(config, null, 401),
        );
      return response(config, { data: "ok" });
    },
  });
  const api = createCaller({
    client,
    refresh: async () => {
      refreshes++;
      await Promise.resolve();
      authenticated = true;
      return true;
    },
  });
  assert.deepEqual(
    await Promise.all([api.http.get("/one"), api.http.get("/two")]),
    ["ok", "ok"],
  );
  assert.equal(refreshes, 1);
  assert.equal(requests, 4);
  authenticated = false;
  await assert.rejects(api.http.post("/one", { value: 1 }));
  await assert.rejects(api.http.get("/auth/me"));
  assert.equal(refreshes, 1);
  assert.equal(
    await api.http.post("/one", { value: 1 }, { retryUnsafe: true }),
    "ok",
  );
  assert.equal(refreshes, 2);
});

test("caller bypasses baseURL with null; never leaks raw Axios credentials in an error", async () => {
  let observed!: InternalAxiosRequestConfig;
  const client = axios.create({
    baseURL: "https://upstream.example",
    adapter: async (config) => {
      observed = config;
      throw new AxiosError(
        "private-token",
        "ERR_BAD_REQUEST",
        config,
        undefined,
        response(config, { secret: "private-token" }, 403),
      );
    },
  });
  const api = createCaller({ client });
  try {
    await api.caller({ url: "/same-origin", baseURL: null });
    assert.fail();
  } catch (error) {
    assert.ok(error instanceof CallerError);
    assert.equal(error.status, 403);
    assert.equal(JSON.stringify(error).includes("private-token"), false);
    assert.equal(error.message.includes("private-token"), false);
    assert.equal("cause" in error, false);
  }
  assert.equal(observed.baseURL, "");
  assert.equal(
    normalizeCallerError(new Error("secret")).message,
    "Request failed",
  );
});
