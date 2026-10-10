import type { FetcherOptions } from "@/utils/interface";
import {
  AxiosHeaders,
  type AxiosInstance,
  type AxiosResponse,
  type RawAxiosHeaders,
} from "axios";

/** App owns instance setup, adapter selection, authentication and destination policy. */
export function createFetcher(client: Pick<AxiosInstance, "request">) {
  return async function fetcher<
    Data = unknown,
    Body = unknown,
    Params = Record<string, unknown>,
  >(options: FetcherOptions<Body, Params>): Promise<AxiosResponse<Data, Body>> {
    const {
      url,
      method,
      body,
      params,
      headers,
      cache,
      credentials,
      redirect,
      maxRedirects,
      ...config
    } = options;
    const nextHeaders = new AxiosHeaders(
      headers as RawAxiosHeaders | AxiosHeaders | undefined,
    );
    if (cache === "no-store")
      nextHeaders.set("Cache-Control", "no-store", false);
    else if (cache === "no-cache" || cache === "reload")
      nextHeaders.set("Cache-Control", "no-cache", false);
    const response = await client.request<
      Data,
      AxiosResponse<Data, Body>,
      Body
    >({
      ...config,
      url: String(url),
      method,
      data: body,
      params,
      headers: nextHeaders,
      maxRedirects:
        redirect === "manual" || redirect === "error" ? 0 : maxRedirects,
      ...(credentials === undefined
        ? {}
        : { withCredentials: credentials === "include" }),
    });
    if (redirect === "error" && response.status >= 300 && response.status < 400)
      throw new Error("Redirect refused");
    return response;
  };
}

export type { FetcherOptions } from "@/utils/interface";
