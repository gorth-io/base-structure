import type { AuthRetryInput, AuthRetryOptions } from "@/utils/interface";

/** Waiter cancellation must not abort a refresh needed by other requests. */
export async function waitForAuthOperation<Value>(
  operation: Promise<Value>,
  signal?: AbortSignal,
): Promise<Value> {
  if (!signal) return await operation;
  return await new Promise<Value>((resolve, reject) => {
    const abort = () => {
      signal.removeEventListener("abort", abort);
      reject(signal.reason);
    };
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
    // Observe even a cancelled waiter's operation so a late rejection is handled.
    void (async () => {
      try {
        resolve(await operation);
      } catch (error) {
        reject(error);
      } finally {
        signal.removeEventListener("abort", abort);
      }
    })();
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
    let operation!: Promise<boolean>;
    operation = (async () => {
      // Register the flight before invoking an adapter that may throw/re-enter.
      await Promise.resolve();
      try {
        if (signal.aborted || disposed || version !== generation) return false;
        const ok = await options.refresh(signal);
        return ok && version === generation && !disposed && !signal.aborted;
      } catch {
        return false;
      } finally {
        if (flight === operation) flight = undefined;
      }
    })();
    flight = operation;
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
        return await request();
      }
    },
    reset,
    dispose() {
      disposed = true;
      reset();
    },
  };
}

export type { AuthRetryInput, AuthRetryOptions } from "@/utils/interface";
