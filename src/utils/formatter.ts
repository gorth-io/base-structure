import type {
  AuthIdentity,
  DesktopRpcResponse,
  OAuthIdentityClaims,
} from "@/utils/interface";
import type { AxiosResponse } from "axios";

/** Call only after provider identity validation. Never project authorization roles. */
export function formatOAuthIdentity(data: OAuthIdentityClaims): AuthIdentity {
  return {
    subject: data.sub,
    name: data.name,
    email: data.email,
    emailVerified: data.email_verified,
    username: data.preferred_username,
    image: data.picture,
  };
}

export function formatEpochMilliseconds(value: Date | string | number): number {
  return value instanceof Date
    ? value.getTime()
    : typeof value === "string"
      ? Date.parse(value)
      : value;
}

export function formatRpcFailure(
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

export function normalizeAccelerator(value: string): string {
  if (!value.trim()) return "";
  const parts = value.split("+").map((part) => part.trim());
  const key = parts.pop()!.replace(/^Arrow/, "");
  if (
    !/^(?:[a-z0-9,./;[\]\\-]|Tab|Space|Plus|Enter|Backspace|Delete|Escape|Up|Down|Left|Right|F(?:[1-9]|1[0-9]|2[0-4]))$/i.test(
      key,
    )
  )
    throw new Error("Choose a letter, number, function key or navigation key.");
  const order = ["CmdOrCtrl", "Ctrl", "Alt", "Shift", "Super"];
  if (
    parts.some((part) => !order.includes(part)) ||
    new Set(parts).size !== parts.length ||
    (!parts.some((part) =>
      ["CmdOrCtrl", "Ctrl", "Alt", "Super"].includes(part),
    ) &&
      !/^F\d+$/i.test(key))
  )
    throw new Error("Use Command/Control, Alt, or a function key.");
  const names = [
    "Tab",
    "Space",
    "Plus",
    "Enter",
    "Backspace",
    "Delete",
    "Escape",
    "Up",
    "Down",
    "Left",
    "Right",
  ];
  return [
    ...order.filter((part) => parts.includes(part)),
    names.find((part) => part.toLowerCase() === key.toLowerCase()) ??
      key.toUpperCase(),
  ].join("+");
}

export function shortcutIdentity(accelerator: string, isMac: boolean): string {
  return accelerator
    .replace("CmdOrCtrl", isMac ? "Super" : "Ctrl")
    .split("+")
    .sort()
    .join("+");
}

export function formatResponseHeaders(response: AxiosResponse<unknown>) {
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

export function formatResponseBody(
  data: unknown,
  headers: Headers,
): BodyInit | null {
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
