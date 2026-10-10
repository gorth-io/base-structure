import type { AxiosResponse } from "axios";

export interface WebResponseOptions {
  /** Explicitly empty a successful body, as distinct from JSON null. */
  emptyBody?: boolean;
  /** Node streams need an app/runtime-specific conversion. */
  mapBody?(data: unknown): BodyInit | null;
}

function responseHeaders(response: AxiosResponse<unknown>) {
  const headers = new Headers();
  for (const [name, value] of Object.entries(response.headers)) {
    if (value === undefined || value === null || value === false) continue;
    for (const item of Array.isArray(value) ? value : [value])
      headers.append(name, String(item));
  }
  for (const name of (headers.get("connection") ?? "").split(",")) {
    if (name.trim()) headers.delete(name.trim());
  }
  // Axios may have decompressed or reserialized the payload. These wire headers
  // would otherwise make the downstream browser decode/count it a second time.
  for (const name of [
    "content-length",
    "content-encoding",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "trailer",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
  ])
    headers.delete(name);
  return headers;
}

function bodyOf(data: unknown, headers: Headers): BodyInit | null {
  if (data === undefined) return null;
  if (
    typeof data === "string" ||
    data instanceof Blob ||
    data instanceof ReadableStream
  )
    return data;
  if (data instanceof ArrayBuffer) return data;
  if (ArrayBuffer.isView(data)) {
    const bytes = new Uint8Array(data.byteLength);
    bytes.set(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
    return bytes;
  }
  if (data instanceof URLSearchParams || data instanceof FormData) return data;
  if (typeof data === "object" && data !== null && "pipe" in data)
    throw new TypeError("Supply mapBody for a Node stream");
  if (!headers.has("content-type"))
    headers.set("content-type", "application/json");
  return JSON.stringify(data);
}

/** Preserves multiple Set-Cookie values and JSON null; 204/205/304 have no body. */
export function toWebResponse<Data>(
  response: AxiosResponse<Data>,
  options: WebResponseOptions = {},
): Response {
  const headers = responseHeaders(response);
  const body =
    options.emptyBody || [204, 205, 304].includes(response.status)
      ? null
      : options.mapBody
        ? options.mapBody(response.data)
        : bodyOf(response.data, headers);
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
