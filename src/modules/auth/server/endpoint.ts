import { AuthError } from "../interface";

/** Shared validation only: app supplies exact origins and development policy. */
export function validateAuthEndpoint(
  value: string,
  options: {
    origins?: readonly string[];
    allowLoopbackHttp?: boolean;
    allowedPath?(url: URL): boolean;
  },
  rejected = false,
): URL {
  try {
    const url = new URL(value);
    if (
      url.username ||
      url.password ||
      url.hash ||
      url.search ||
      (url.protocol !== "https:" &&
        !(
          options.allowLoopbackHttp === true &&
          url.protocol === "http:" &&
          ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
        )) ||
      (options.origins && !options.origins.includes(url.origin)) ||
      (options.allowedPath && !options.allowedPath(url))
    )
      throw new Error();
    return url;
  } catch {
    throw new AuthError(rejected ? "rejected" : "invalid_configuration");
  }
}
