import { waitForAuthOperation } from "@/modules/auth/client/retry";
import { AuthError } from "@/modules/auth/interface";
import type { VerifiedLogin } from "@/modules/auth/server/interface";
import type { DesktopLoginInput, DesktopLoginOptions } from "@/utils/interface";

/** MAIN PROCESS ONLY. No Electron dependency, renderer tokens, env reads, or HTTP listener. */
export function createDesktopLogin(options: DesktopLoginOptions) {
  let busy = false;
  const now = options.now ?? Date.now;

  async function login(input: DesktopLoginInput = {}): Promise<VerifiedLogin> {
    if (busy) throw new AuthError("unavailable");
    busy = true;
    const controller = new AbortController();
    let unregister: (() => void) | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let rejectCallback: ((error: AuthError) => void) | undefined;
    const abort = () => {
      controller.abort();
      rejectCallback?.(new AuthError("cancelled"));
    };
    input.signal?.addEventListener("abort", abort, { once: true });
    try {
      if (input.signal?.aborted) throw new AuthError("cancelled");
      const { url, transaction } = await options.provider.startLogin(
        input.returnTo,
        input.prompt,
      );
      const redirect = new URL(transaction.redirectUri);
      // Explicit fixed loopback callback, like the existing desktop apps. The app
      // may forward an internal scheme to this listener, but must not treat it as verified.
      if (
        redirect.protocol !== "http:" ||
        !["localhost", "127.0.0.1", "[::1]"].includes(redirect.hostname) ||
        !redirect.port ||
        redirect.username ||
        redirect.password ||
        redirect.search ||
        redirect.hash ||
        transaction.expiresAt <= now() ||
        transaction.expiresAt > now() + 600_000
      )
        throw new AuthError("invalid_configuration");
      const callback = new Promise<string>((resolve, reject) => {
        rejectCallback = reject;
        let accepted = false;
        unregister = options.adapter.listen((value) => {
          if (accepted || value.length > 8192) return false;
          let candidate: URL;
          try {
            candidate = new URL(value);
          } catch {
            return false;
          }
          if (
            candidate.origin !== redirect.origin ||
            candidate.pathname !== redirect.pathname ||
            candidate.username ||
            candidate.password ||
            candidate.hash ||
            candidate.searchParams.getAll("state").length !== 1 ||
            candidate.searchParams.get("state") !== transaction.state
          )
            return false;
          accepted = true;
          resolve(value);
          return true;
        });
        timer = setTimeout(() => {
          controller.abort();
          reject(new AuthError("cancelled"));
        }, transaction.expiresAt - now());
      });
      // Subscribe before open: the window/listener can synchronously deliver a callback.
      void (async () => {
        try {
          await callback;
        } catch {
          /* The main wait reports cancellation; observe an early callback failure. */
        }
      })();
      controller.signal.throwIfAborted();
      // Bound BOTH navigation and callback wait; a hanging window open cannot skip timeout.
      const navigation = async () => {
        await options.adapter.open(url, controller.signal);
        return await callback;
      };
      const value = await waitForAuthOperation(navigation(), controller.signal);
      const result = await options.provider.finishLogin(
        value,
        transaction,
        controller.signal,
      );
      controller.signal.throwIfAborted();
      return result;
    } catch (error) {
      if (controller.signal.aborted || input.signal?.aborted)
        throw new AuthError("cancelled");
      if (error instanceof AuthError) throw error;
      throw new AuthError("unavailable");
    } finally {
      if (timer) clearTimeout(timer);
      try {
        unregister?.();
      } finally {
        input.signal?.removeEventListener("abort", abort);
        try {
          await options.adapter.close();
        } catch {
          /* Cleanup failure must not override the auth result. */
        } finally {
          busy = false;
        }
      }
    }
  }
  return { login };
}

export type {
  DesktopLoginAdapter,
  DesktopLoginInput,
  DesktopLoginOptions,
  DesktopLoginProvider,
} from "@/utils/interface";
