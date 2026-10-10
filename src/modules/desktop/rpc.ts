import { z } from "zod";
import { waitForAuthOperation } from "../auth/client/retry";
import type {
  DesktopRpcPolicy,
  DesktopRpcRequest,
  DesktopRpcResponse,
} from "./interface";

function rpcPolicy(options: DesktopRpcPolicy) {
  const origin = options.origin ?? "https://desktop.invalid";
  const endpoint = options.endpoint ?? "/trpc";
  const maxUrlLength = options.maxUrlLength ?? 2_000_000;
  const maxBodyBytes = options.maxBodyBytes ?? 8_000_000;
  const maxResponseBytes = options.maxResponseBytes ?? 8_000_000;
  const url = new URL(origin);
  if (
    url.origin !== origin ||
    url.protocol !== "https:" ||
    !/^\/[a-zA-Z][a-zA-Z0-9/-]*$/.test(endpoint) ||
    endpoint.endsWith("/") ||
    ![maxUrlLength, maxBodyBytes, maxResponseBytes].every(
      (value) =>
        Number.isSafeInteger(value) && value > 0 && value <= 16_000_000,
    )
  )
    throw new TypeError("Invalid desktop RPC policy");
  return { origin, endpoint, maxUrlLength, maxBodyBytes, maxResponseBytes };
}
function requestSchema(policy: ReturnType<typeof rpcPolicy>) {
  return z
    .object({
      url: z
        .string()
        .max(policy.maxUrlLength)
        .refine((value) => {
          try {
            const url = new URL(value);
            const path = url.pathname.slice(policy.endpoint.length + 1);
            return (
              url.origin === policy.origin &&
              url.pathname.startsWith(policy.endpoint + "/") &&
              /^[a-zA-Z][a-zA-Z0-9.]*$/.test(path) &&
              !url.username &&
              !url.password &&
              !url.hash
            );
          } catch {
            return false;
          }
        }),
      method: z.enum(["GET", "POST"]),
      body: z.string().max(policy.maxBodyBytes).optional(),
    })
    .strict()
    .refine(
      (input) =>
        (input.method !== "GET" || input.body === undefined) &&
        (input.body === undefined ||
          new TextEncoder().encode(input.body).length <= policy.maxBodyBytes),
    );
}
function failure(
  status: number,
  message: string,
  code: number,
  label: string,
): DesktopRpcResponse {
  return {
    status,
    body: JSON.stringify({
      error: { message, code, data: { code: label, httpStatus: status } },
    }),
  };
}

/** Main-process packet validation. Supply tRPC's fetchRequestHandler as handle. */
export function createDesktopRpcHandler(
  options: DesktopRpcPolicy & {
    handle(request: Request): Promise<Response>;
  },
) {
  const policy = rpcPolicy(options);
  const schema = requestSchema(policy);
  return async function handleRpcRequest(
    input: unknown,
  ): Promise<DesktopRpcResponse> {
    const parsed = schema.safeParse(input);
    if (!parsed.success)
      return failure(
        400,
        "Invalid desktop RPC request.",
        -32600,
        "BAD_REQUEST",
      );
    try {
      const response = await options.handle(
        new Request(parsed.data.url, {
          method: parsed.data.method,
          body: parsed.data.body,
          headers: { "content-type": "application/json" },
        }),
      );
      const body = await boundedResponseText(response, policy.maxResponseBytes);
      if (response.status < 200 || response.status > 599) throw new Error();
      return { status: response.status, body };
    } catch {
      return failure(
        500,
        "Desktop RPC unavailable.",
        -32603,
        "INTERNAL_SERVER_ERROR",
      );
    }
  };
}
async function boundedResponseText(response: Response, limit: number) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > limit) {
        await reader.cancel();
        throw new Error("RPC response too large");
      }
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return new TextDecoder().decode(bytes);
}

/** No network request: URL is protocol metadata passed to app-owned trusted IPC. */
export function createDesktopRpcTransport(
  options: DesktopRpcPolicy & {
    request(
      input: DesktopRpcRequest,
      signal?: AbortSignal,
    ): Promise<DesktopRpcResponse>;
  },
) {
  const policy = rpcPolicy(options);
  const schema = requestSchema(policy);
  return async function rpcFetch(
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> {
    const signal =
      init?.signal ?? (input instanceof Request ? input.signal : undefined);
    signal?.throwIfAborted();
    const method = (
      init?.method ?? (input instanceof Request ? input.method : "GET")
    ).toUpperCase();
    const body =
      init?.body ??
      (input instanceof Request && method === "POST"
        ? await boundedResponseText(
            new Response(input.body),
            policy.maxBodyBytes,
          )
        : undefined);
    if (body !== undefined && typeof body !== "string")
      throw new TypeError("Desktop RPC body must be text");
    const parsed = schema.parse({
      url: input instanceof Request ? input.url : String(input),
      method,
      ...(body === undefined ? {} : { body }),
    });
    signal?.throwIfAborted();
    const result = await waitForAuthOperation(
      options.request(parsed, signal ?? undefined),
      signal ?? undefined,
    );
    signal?.throwIfAborted();
    if (
      !Number.isInteger(result.status) ||
      result.status < 200 ||
      result.status > 599 ||
      typeof result.body !== "string" ||
      new TextEncoder().encode(result.body).length > policy.maxResponseBytes
    )
      throw new TypeError("Invalid desktop RPC response");
    return new Response(
      [204, 205, 304].includes(result.status) ? null : result.body,
      {
        status: result.status,
        headers: { "content-type": "application/json" },
      },
    );
  };
}
