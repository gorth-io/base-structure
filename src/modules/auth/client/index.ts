import { AuthError, type PublicSession } from "@/modules/auth/interface";
import { resolveReturnPath } from "@/modules/auth/policy";
import type {
  AuthClientAdapter,
  AuthClientState,
  AuthLoginInput,
} from "@/utils/interface";

export { createAuthRetry } from "@/modules/auth/client/retry";
export type {
  AuthRetryInput,
  AuthRetryOptions,
} from "@/modules/auth/client/retry";
export { createSessionAuthAdapter } from "@/modules/auth/client/session-adapter";
export type {
  SessionAuthAdapterOptions,
  SessionSdkResult,
  SessionSdkSession,
} from "@/modules/auth/client/session-adapter";
export { AuthError } from "@/modules/auth/interface";
export type {
  AuthErrorCode,
  AuthIdentity,
  PublicSession,
} from "@/modules/auth/interface";
export {
  createAuthFreshnessPolicy,
  createAuthPolicy,
} from "@/modules/auth/policy";
export type {
  AuthFreshness,
  AuthFreshnessInput,
  AuthPolicy,
} from "@/utils/interface";

/** Vanilla external store: usable with React.useSyncExternalStore, Vite, and preload IPC. */
export function createAuthClient<User>(adapter: AuthClientAdapter<User>) {
  let state: Readonly<AuthClientState<User>> = Object.freeze({
    status: "loading",
    session: null,
    busy: false,
    error: null,
  });
  const listeners = new Set<() => void>();
  let generation = 0;
  let disposed = false;
  let controller: AbortController | undefined;
  let readFlight: Promise<PublicSession<User> | null> | undefined;
  let actionFlight: Promise<void> | undefined;

  function publish(next: AuthClientState<User>) {
    if (disposed) return;
    state = Object.freeze(next);
    for (const listener of listeners) {
      try {
        listener();
      } catch {
        /* A view observer must not change auth control flow. */
      }
    }
  }

  function reset() {
    if (disposed) throw new AuthError("cancelled");
    generation++;
    controller?.abort();
    controller = new AbortController();
    readFlight = undefined;
    return { signal: controller.signal, version: generation };
  }

  function load(): Promise<PublicSession<User> | null> {
    if (disposed) return Promise.reject(new AuthError("cancelled"));
    if (actionFlight) {
      return (async () => {
        await actionFlight;
        return state.session;
      })();
    }
    if (readFlight) return readFlight;
    const { signal, version } = reset();
    // Background revalidation must not flash an authenticated view to signed-out.
    // The app/API still verifies authorization on every protected operation.
    publish({ ...state, busy: true, error: null });
    let flight!: Promise<PublicSession<User> | null>;
    flight = (async () => {
      await Promise.resolve();
      try {
        const session = await adapter.read(signal);
        if (version !== generation || disposed) return state.session;
        publish({
          status: session ? "authenticated" : "anonymous",
          session,
          busy: false,
          error: null,
        });
        return session;
      } catch (error) {
        if (version === generation && !disposed) publishFailure(error);
        throw error instanceof AuthError ? error : new AuthError("unavailable");
      } finally {
        if (readFlight === flight) readFlight = undefined;
      }
    })();
    readFlight = flight;
    return flight;
  }

  function publishFailure(error: unknown) {
    publish({
      status: "error",
      session: null,
      busy: false,
      error:
        error instanceof AuthError && error.code !== "invalid_configuration"
          ? error.code
          : "unavailable",
    });
  }

  async function action(kind: "login" | "logout", input: AuthLoginInput = {}) {
    if (actionFlight) throw new AuthError("unavailable");
    const returnTo = resolveReturnPath(input.returnTo);
    const { signal, version } = reset();
    publish({
      status: kind === "logout" ? "anonymous" : "loading",
      session: null,
      busy: true,
      error: null,
    });
    let flight!: Promise<void>;
    flight = (async () => {
      await Promise.resolve();
      try {
        if (kind === "logout") await adapter.logout(signal);
        else {
          const result = await adapter.login(
            { returnTo, prompt: input.prompt },
            signal,
          );
          if (result?.status === "redirecting") return;
        }
        if (version !== generation || disposed) return;
        const session = kind === "logout" ? null : await adapter.read(signal);
        if (version === generation && !disposed)
          publish({
            status: session ? "authenticated" : "anonymous",
            session,
            busy: false,
            error: null,
          });
      } catch (error) {
        if (version === generation && !disposed) publishFailure(error);
        throw error instanceof AuthError ? error : new AuthError("unavailable");
      } finally {
        if (actionFlight === flight) actionFlight = undefined;
      }
    })();
    actionFlight = flight;
    return flight;
  }

  return {
    getSnapshot: () => state,
    subscribe(listener: () => void) {
      if (disposed) throw new AuthError("cancelled");
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    load,
    login: (input?: AuthLoginInput) => action("login", input),
    logout: () => action("logout"),
    dispose() {
      disposed = true;
      generation++;
      controller?.abort();
      listeners.clear();
    },
  };
}

export type {
  AuthClientAdapter,
  AuthClientState,
  AuthLoginInput,
  AuthLoginResult,
} from "@/utils/interface";
