import { isAxiosError } from "axios";

export interface CallerErrorOptions {
  status?: number;
  code?: string;
  /** Opt-in safe endpoint metadata only; never include Axios config/request/cause. */
  details?: unknown;
}

export class CallerError extends Error {
  readonly status?: number;
  readonly code?: string;
  readonly details?: unknown;
  constructor(message: string, options: CallerErrorOptions = {}) {
    super(message);
    this.name = "CallerError";
    this.status = options.status;
    this.code = options.code;
    this.details = options.details;
  }
}

/** Do not propagate raw Axios errors (which contain credentials and request bodies). */
export function normalizeCallerError(error: unknown): CallerError {
  if (error instanceof CallerError) return error;
  if (isAxiosError(error)) {
    return new CallerError(
      error.code === "ERR_CANCELED" ? "Request cancelled" : "Request failed",
      {
        status: error.response?.status,
        code: error.code,
      },
    );
  }
  if (error instanceof DOMException && error.name === "AbortError")
    return new CallerError("Request cancelled", { code: "ERR_CANCELED" });
  return new CallerError("Request failed");
}
