import {
  AuthError,
  type PublicSession,
  type AuthErrorCode,
} from "../interface";
import { resolveReturnPath } from "../policy";

export { AuthError } from "../interface";
export type { AuthIdentity, AuthErrorCode, PublicSession } from "../interface";

export interface AuthClientAdapter<User> {
  /** Same-origin app endpoint on web; trusted preload IPC on desktop. No OAuth tokens. */
  read(signal: AbortSignal): Promise<PublicSession<User> | null>;
  login(
    input: {
      returnTo: string;
      prompt?: "login" | "create" | "consent" | "select_account";
    },
    signal: AbortSignal,
  ): Promise<void>;
  logout(signal: AbortSignal): Promise<void>;
}

export interface AuthClientState<User> {
  status: "loading" | "authenticated" | "anonymous" | "error";
  session: PublicSession<User> | null;
  busy: boolean;
  error: Exclude<AuthErrorCode, "invalid_configuration"> | null;
}

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
    if (actionFlight) return actionFlight.then(() => state.session);
    if (readFlight) return readFlight;
    const { signal, version } = reset();
    publish({ status: "loading", session: null, busy: true, error: null });
    const flight = Promise.resolve()
      .then(() => adapter.read(signal))
      .then(
        (session) => {
          if (version !== generation || disposed) return state.session;
          publish({
            status: session ? "authenticated" : "anonymous",
            session,
            busy: false,
            error: null,
          });
          return session;
        },
        (error: unknown) => {
          if (version === generation && !disposed)
            publish({
              status: "error",
              session: null,
              busy: false,
              error:
                error instanceof AuthError &&
                error.code !== "invalid_configuration"
                  ? error.code
                  : "unavailable",
            });
          throw error instanceof AuthError
            ? error
            : new AuthError("unavailable");
        },
      )
      .finally(() => {
        if (readFlight === flight) readFlight = undefined;
      });
    readFlight = flight;
    return flight;
  }

  function action(
    kind: "login" | "logout",
    input: {
      returnTo?: string;
      prompt?: "login" | "create" | "consent" | "select_account";
    } = {},
  ) {
    if (actionFlight) return Promise.reject(new AuthError("unavailable"));
    const returnTo = resolveReturnPath(input.returnTo);
    const { signal, version } = reset();
    publish({
      status: kind === "logout" ? "anonymous" : "loading",
      session: null,
      busy: true,
      error: null,
    });
    const flight = Promise.resolve()
      .then(async () => {
        if (kind === "logout") await adapter.logout(signal);
        else await adapter.login({ returnTo, prompt: input.prompt }, signal);
        if (version !== generation || disposed) return;
        const session = kind === "logout" ? null : await adapter.read(signal);
        if (version === generation && !disposed)
          publish({
            status: session ? "authenticated" : "anonymous",
            session,
            busy: false,
            error: null,
          });
      })
      .catch((error: unknown) => {
        if (version === generation && !disposed)
          publish({
            status: "error",
            session: null,
            busy: false,
            error:
              error instanceof AuthError &&
              error.code !== "invalid_configuration"
                ? error.code
                : "unavailable",
          });
        throw error instanceof AuthError ? error : new AuthError("unavailable");
      })
      .finally(() => {
        if (actionFlight === flight) actionFlight = undefined;
      });
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
    login: (input?: {
      returnTo?: string;
      prompt?: "login" | "create" | "consent" | "select_account";
    }) => action("login", input),
    logout: () => action("logout"),
    dispose() {
      disposed = true;
      generation++;
      controller?.abort();
      listeners.clear();
    },
  };
}
