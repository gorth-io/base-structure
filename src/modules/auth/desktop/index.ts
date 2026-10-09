import { AuthError } from "../interface";
import type { LoginTransaction, VerifiedLogin } from "../server/interface";

export interface DesktopLoginProvider {
  startLogin(
    returnTo?: string,
    prompt?: "login" | "create" | "consent" | "select_account",
  ): Promise<{ url: string; transaction: LoginTransaction }>;
  finishLogin(
    callback: string,
    transaction: LoginTransaction,
    signal?: AbortSignal,
  ): Promise<VerifiedLogin>;
}

export interface DesktopLoginAdapter {
  /** Register before navigating. App owns its loopback listener/auth window and cleanup. */
  listen(receive: (url: string) => boolean): () => void;
  open(url: string, signal: AbortSignal): Promise<void>;
  close(): Promise<void>;
}

/** MAIN PROCESS ONLY. No Electron dependency, renderer tokens, env reads, or HTTP listener. */
export function createDesktopLogin(options: {
  provider: DesktopLoginProvider;
  adapter: DesktopLoginAdapter;
  now?: () => number;
}) {
  let busy = false;
  const now = options.now ?? Date.now;

  async function login(
    input: {
      returnTo?: string;
      prompt?: "login" | "create" | "consent" | "select_account";
      signal?: AbortSignal;
    } = {},
  ): Promise<VerifiedLogin> {
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
      void callback.catch(() => {});
      controller.signal.throwIfAborted();
      // Bound BOTH navigation and callback wait; a hanging window open cannot skip timeout.
      const value = await Promise.race([
        options.adapter.open(url, controller.signal).then(() => callback),
        new Promise<never>((_, reject) => {
          controller.signal.addEventListener(
            "abort",
            () => reject(new AuthError("cancelled")),
            { once: true },
          );
        }),
      ]);
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
          await options.adapter.close().catch(() => {});
        } finally {
          busy = false;
        }
      }
    }
  }
  return { login };
}
