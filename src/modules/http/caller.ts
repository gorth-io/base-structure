import { createAuthRetry } from "@/modules/auth/client/retry";
import { CallerError, normalizeCallerError } from "@/modules/http/error";
import { createFetcher } from "@/modules/http/fetcher";
import type {
  CallerMethodOptions,
  CallerOptions,
  CallerRequestOptions,
} from "@/utils/interface";
import { isAxiosError, type ResponseType } from "axios";

export function createCaller(options: CallerOptions) {
  const fetcher = createFetcher(options.client);
  const retry = options.refresh
    ? createAuthRetry({
        refresh: options.refresh,
        getStatus: (error) =>
          isAxiosError(error) ? error.response?.status : undefined,
      })
    : undefined;

  function notify<Data>(
    kind: "success" | "error",
    setting: CallerRequestOptions<Data>["toast"],
    value: Data | CallerError,
  ) {
    if (setting === false || !options.notify) return;
    const configured = typeof setting === "object" ? setting[kind] : undefined;
    const message =
      typeof configured === "function"
        ? (configured as (value: Data | CallerError) => string)(value)
        : (configured ??
          (kind === "error" ? (value as CallerError).message : undefined));
    if (message) {
      try {
        options.notify(kind, message);
      } catch {
        /* UI observers cannot change request outcome. */
      }
    }
  }

  async function caller<
    Data = unknown,
    Body = unknown,
    Params = Record<string, unknown>,
  >(input: CallerRequestOptions<Data, Body, Params>): Promise<Data> {
    const {
      url,
      method = "GET",
      body,
      params,
      query,
      baseURL,
      auth = true,
      unwrapData = true,
      schema,
      responseHandler,
      toast,
      onSuccess,
      onError,
      retryUnsafe,
      ...config
    } = input;
    const upperMethod = method.toUpperCase();
    const request = () =>
      fetcher<unknown, Body, Params>({
        ...config,
        url,
        method,
        body,
        params: query ?? params,
        // null deliberately bypasses an instance's configured baseURL.
        baseURL: baseURL === null ? "" : baseURL,
        responseType:
          config.responseType ??
          (typeof responseHandler === "string" &&
          responseHandler !== "content-type"
            ? responseHandler === "arrayBuffer"
              ? "arraybuffer"
              : (responseHandler as ResponseType)
            : undefined),
      });
    try {
      config.signal?.throwIfAborted();
      const signal = config.signal as AbortSignal | undefined;
      const response = retry
        ? await retry.withAuthRetry(request, {
            signal,
            enabled:
              auth &&
              (options.canRetry?.(url) ??
                !/(?:^|\/)auth(?:\/|\?|$)/.test(url)) &&
              (["GET", "HEAD", "OPTIONS"].includes(upperMethod) ||
                retryUnsafe === true),
          })
        : await request();
      let data: unknown =
        response.status === 204 || upperMethod === "HEAD"
          ? null
          : typeof responseHandler === "function"
            ? await responseHandler(response)
            : unwrapData &&
                response.data !== null &&
                typeof response.data === "object" &&
                "data" in response.data
              ? response.data.data
              : response.data;
      if (schema) data = await schema.parseAsync(data);
      const result = data as Data;
      await onSuccess?.(result);
      notify("success", toast, result);
      return result;
    } catch (error) {
      let normalized = normalizeCallerError(error);
      if (options.mapError)
        normalized = options.mapError(
          normalized,
          isAxiosError(error) ? error.response?.data : undefined,
        );
      await onError?.(normalized);
      if (normalized.code !== "ERR_CANCELED")
        notify("error", toast, normalized);
      throw normalized;
    }
  }

  const http = {
    request: caller,
    get<Data = unknown, Params = Record<string, unknown>>(
      url: string,
      input: CallerMethodOptions<Data, never, Params> = {},
    ) {
      return caller<Data, never, Params>({ ...input, url, method: "GET" });
    },
    post<Data = unknown, Body = unknown, Params = Record<string, unknown>>(
      url: string,
      body?: Body,
      input: CallerMethodOptions<Data, Body, Params> = {},
    ) {
      return caller<Data, Body, Params>({
        ...input,
        url,
        method: "POST",
        body,
      });
    },
    put<Data = unknown, Body = unknown, Params = Record<string, unknown>>(
      url: string,
      body?: Body,
      input: CallerMethodOptions<Data, Body, Params> = {},
    ) {
      return caller<Data, Body, Params>({ ...input, url, method: "PUT", body });
    },
    patch<Data = unknown, Body = unknown, Params = Record<string, unknown>>(
      url: string,
      body?: Body,
      input: CallerMethodOptions<Data, Body, Params> = {},
    ) {
      return caller<Data, Body, Params>({
        ...input,
        url,
        method: "PATCH",
        body,
      });
    },
    delete<Data = unknown, Body = unknown, Params = Record<string, unknown>>(
      url: string,
      input: Omit<
        CallerRequestOptions<Data, Body, Params>,
        "url" | "method"
      > = {},
    ) {
      return caller<Data, Body, Params>({ ...input, url, method: "DELETE" });
    },
    head<Data = unknown, Params = Record<string, unknown>>(
      url: string,
      input: CallerMethodOptions<Data, never, Params> = {},
    ) {
      return caller<Data, never, Params>({ ...input, url, method: "HEAD" });
    },
    options<Data = unknown, Body = unknown, Params = Record<string, unknown>>(
      url: string,
      input: Omit<
        CallerRequestOptions<Data, Body, Params>,
        "url" | "method"
      > = {},
    ) {
      return caller<Data, Body, Params>({ ...input, url, method: "OPTIONS" });
    },
  };
  return {
    caller,
    http,
    reset: () => retry?.reset(),
    dispose: () => retry?.dispose(),
  };
}

export type {
  CallerOptions,
  CallerRequestOptions,
  CallerResponseHandler,
  CallerToastOptions,
} from "@/utils/interface";
