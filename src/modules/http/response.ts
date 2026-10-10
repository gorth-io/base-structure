import { formatResponseBody, formatResponseHeaders } from "@/utils/formatter";
import type { WebResponseOptions } from "@/utils/interface";
import type { AxiosResponse } from "axios";

/** Preserves multiple Set-Cookie values and JSON null; 204/205/304 have no body. */
export function toWebResponse<Data>(
  response: AxiosResponse<Data>,
  options: WebResponseOptions = {},
): Response {
  const headers = formatResponseHeaders(response);
  const body =
    options.emptyBody || [204, 205, 304].includes(response.status)
      ? null
      : options.mapBody
        ? options.mapBody(response.data)
        : formatResponseBody(response.data, headers);
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export type { WebResponseOptions } from "@/utils/interface";
