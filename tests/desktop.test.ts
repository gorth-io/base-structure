import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createDesktopRpcHandler,
  createDesktopRpcTransport,
  normalizeAccelerator,
  shortcutIdentity,
  createShortcutValidator,
} from "../src/modules/desktop";
import { deferred } from "./auth.fixture";

test("desktop RPC roundtrip delegates to injected handler/IPC without network or Electron", async () => {
  const handler = createDesktopRpcHandler({
    handle: async (request) =>
      Response.json({
        path: new URL(request.url).pathname,
        body: await request.json(),
      }),
  });
  const fetch = createDesktopRpcTransport({ request: handler });
  const response = await fetch("https://desktop.invalid/trpc/item.update", {
    method: "POST",
    body: '{"count":2}',
  });
  assert.deepEqual(await response.json(), {
    path: "/trpc/item.update",
    body: { count: 2 },
  });
});

test("main rejects foreign origin, bad methods/path/body, excess fields and byte limits", async () => {
  let calls = 0;
  const handler = createDesktopRpcHandler({
    maxBodyBytes: 3,
    handle: async () => {
      calls++;
      return Response.json({ ok: true });
    },
  });
  const base = { url: "https://desktop.invalid/trpc/item.get", method: "GET" };
  const packets = [
    { ...base, url: "https://evil.example/trpc/item.get" },
    { ...base, url: "https://desktop.invalid/admin" },
    { ...base, url: "https://user@desktop.invalid/trpc/item.get" },
    { ...base, url: base.url + "#fragment" },
    { ...base, method: "DELETE" },
    { ...base, body: "{}" },
    { ...base, identity: "admin" },
    { ...base, method: "POST", body: "éé" },
  ];
  for (const packet of packets)
    assert.equal((await handler(packet)).status, 400);
  assert.equal(calls, 0);
});

test("RPC returns sanitized handler failures and bounds streaming responses", async () => {
  const handler = createDesktopRpcHandler({
    handle: async () => {
      throw new Error("private-token");
    },
  });
  const result = await handler({
    url: "https://desktop.invalid/trpc/item.get",
    method: "GET",
  });
  assert.equal(result.status, 500);
  assert.equal(result.body.includes("private-token"), false);
  let cancelled = false;
  const oversized = createDesktopRpcHandler({
    maxResponseBytes: 3,
    handle: async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode("too large"));
          },
          cancel() {
            cancelled = true;
          },
        }),
      ),
  });
  assert.equal(
    (
      await oversized({
        url: "https://desktop.invalid/trpc/item.get",
        method: "GET",
      })
    ).status,
    500,
  );
  assert.equal(cancelled, true);
});

test("RPC checks cancellation and rejects invalid IPC responses", async () => {
  const controller = new AbortController();
  controller.abort();
  const fetch = createDesktopRpcTransport({
    request: async () => {
      assert.fail("must not call IPC");
    },
  });
  await assert.rejects(
    fetch("https://desktop.invalid/trpc/item.get", {
      signal: controller.signal,
    }),
    { name: "AbortError" },
  );
  const broken = createDesktopRpcTransport({
    request: async () => ({ status: 99, body: "bad" }),
  });
  await assert.rejects(
    broken("https://desktop.invalid/trpc/item.get"),
    /Invalid desktop RPC response/,
  );
  const pending = deferred<{ status: number; body: string }>();
  const next = new AbortController();
  const operation = createDesktopRpcTransport({
    request: () => pending.promise,
  })("https://desktop.invalid/trpc/item.get", { signal: next.signal });
  next.abort();
  await assert.rejects(operation, { name: "AbortError" });
  pending.resolve({ status: 200, body: "{}" });
});

test("shortcut normalization, platform equivalence, duplicates and app-owned reserved bindings", () => {
  const shortcuts = [
    {
      id: "one",
      label: "One",
      defaultAccelerator: "CmdOrCtrl+T",
      accelerator: "CmdOrCtrl+T",
    },
    {
      id: "two",
      label: "Two",
      defaultAccelerator: "CmdOrCtrl+F",
      accelerator: "CmdOrCtrl+F",
    },
  ];
  assert.equal(
    normalizeAccelerator("Shift + CmdOrCtrl + t"),
    "CmdOrCtrl+Shift+T",
  );
  assert.equal(normalizeAccelerator("Ctrl+ArrowUp"), "Ctrl+Up");
  assert.equal(
    shortcutIdentity("CmdOrCtrl+T", true),
    shortcutIdentity("Super+T", true),
  );
  const validate = createShortcutValidator({
    isMac: true,
    reserved: ["CmdOrCtrl+Q"],
  });
  assert.equal(validate(shortcuts, "one", ""), "");
  assert.throws(
    () => validate(shortcuts, "one", "Super+F"),
    /already assigned/,
  );
  assert.throws(() => validate(shortcuts, "one", "CmdOrCtrl+Q"), /reserved/);
  assert.throws(() => validate(shortcuts, "unknown", "Ctrl+T"), /Unknown/);
  assert.throws(() => normalizeAccelerator("Shift+T"));
  assert.throws(() => normalizeAccelerator("Ctrl+Ctrl+T"));
  assert.throws(
    () =>
      createShortcutValidator({ isMac: false, reserved: [] })(
        shortcuts,
        "one",
        "Ctrl+CmdOrCtrl+T",
      ),
    /Duplicate/,
  );
});
