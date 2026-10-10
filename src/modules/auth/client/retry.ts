export interface AuthRetryOptions {
  /** App session read/refresh or trusted IPC; never return OAuth tokens. */
  refresh(signal: AbortSignal): Promise<boolean>;
  getStatus(error: unknown): number | undefined;
}

export interface AuthRetryInput {
  enabled?: boolean;
  signal?: AbortSignal;
}

/** Waiter cancellation must not abort a refresh needed by other requests. */
export function waitForAuthOperation<Value>(
  operation: Promise<Value>,
  signal?: AbortSignal,
): Promise<Value> {
  if (!signal) return operation;
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    operation.then(resolve, reject).finally(() => {
      signal.removeEventListener("abort", abort);
    });
  });
}

/** One refresh flight per factory, one retry per request. Reset on logout/account change. */
export function createAuthRetry(options: AuthRetryOptions) {
  let flight: Promise<boolean> | undefined;
  let controller: AbortController | undefined;
  let generation = 0;
  let disposed = false;

  function reset() {
    generation++;
    controller?.abort();
    flight = undefined;
  }

  function refresh() {
    if (flight) return flight;
    controller = new AbortController();
    const signal = controller.signal;
    const version = generation;
    const operation = Promise.resolve()
      .then(() => options.refresh(signal))
      .then(
        (ok) => ok && version === generation && !disposed && !signal.aborted,
      )
      .catch(() => false);
    flight = operation;
    void operation.finally(() => {
      if (flight === operation) flight = undefined;
    });
    return operation;
  }

  return {
    async withAuthRetry<Value>(
      request: () => Promise<Value>,
      input: AuthRetryInput = {},
    ): Promise<Value> {
      input.signal?.throwIfAborted();
      const version = generation;
      try {
        return await request();
      } catch (error) {
        input.signal?.throwIfAborted();
        if (
          disposed ||
          version !== generation ||
          input.enabled === false ||
          options.getStatus(error) !== 401 ||
          !(await waitForAuthOperation(refresh(), input.signal)) ||
          version !== generation ||
          disposed
        )
          throw error;
        input.signal?.throwIfAborted();
        return request();
      }
    },
    reset,
    dispose() {
      disposed = true;
      reset();
    },
  };
}
