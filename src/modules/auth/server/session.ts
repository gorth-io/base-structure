import { AuthError, type AuthPolicy, type PublicSession } from "../interface";
import { createAuthPolicy } from "../policy";
import { fingerprintAuthValue, randomAuthValue } from "./crypto";
import type {
  IdentityAdapter,
  LogoutStorage,
  OAuthProvider,
  SessionStorage,
  StoredSession,
  VerifiedLogin,
} from "./interface";

export interface SessionServiceOptions<User> {
  provider: OAuthProvider;
  storage: SessionStorage<User>;
  revocation: LogoutStorage;
  identity: IdentityAdapter<User>;
  policy?: Partial<AuthPolicy>;
  now?: () => number;
}

function validHandle(handle: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(handle);
}

export function createSessionService<User>(
  options: SessionServiceOptions<User>,
) {
  const policy = createAuthPolicy(options.policy);
  const now = options.now ?? Date.now;
  const { storage, provider, identity } = options;
  const publicSession = (
    session: StoredSession<User>,
  ): PublicSession<User> => ({
    user: session.user,
    expiresAt: session.expiresAt,
  });

  async function create(login: VerifiedLogin) {
    if (
      login.identity.subject !== login.credentials.subject ||
      login.credentials.accessExpiresAt <= now()
    )
      throw new AuthError("rejected");
    const user = await identity.synchronize(login.identity);
    if (!identity.allowed(user)) throw new AuthError("rejected");
    const handle = randomAuthValue();
    const session: StoredSession<User> = {
      key: await fingerprintAuthValue(handle),
      revision: randomAuthValue(),
      binding: provider.binding,
      subject: login.identity.subject,
      sid: login.sid,
      user,
      credentials: login.credentials,
      createdAt: now(),
      verifiedAt: now(),
      expiresAt: Math.min(
        now() + policy.sessionMaxAgeMs,
        login.credentials.refreshExpiresAt ?? Infinity,
        login.credentials.refreshToken
          ? Infinity
          : login.credentials.accessExpiresAt,
      ),
    };
    if (session.expiresAt <= now() || !(await storage.insert(session)))
      throw new AuthError("rejected");
    return { handle, session: publicSession(session) };
  }

  async function get(
    handle: string,
    input: { fresh?: boolean; signal?: AbortSignal } = {},
  ): Promise<PublicSession<User> | null> {
    if (!validHandle(handle)) return null;
    const key = await fingerprintAuthValue(handle);
    return storage.withLock(key, async () => {
      let session = await storage.read(key);
      if (!session) return null;
      if (
        session.key !== key ||
        session.binding !== provider.binding ||
        session.subject !== session.credentials.subject ||
        session.expiresAt <= now() ||
        (await options.revocation.isRevoked({
          subject: session.subject,
          sid: session.sid,
          issuedAt: session.createdAt,
          now: now(),
        }))
      ) {
        await storage.remove(key, session.revision);
        return null;
      }
      const currentUser = await identity.read(session.user);
      if (!currentUser || !identity.allowed(currentUser)) {
        await storage.remove(key, session.revision);
        return null;
      }
      session = { ...session, user: currentUser };
      let rotated = false;

      async function checkpoint(next: StoredSession<User>) {
        const previous = session!;
        next = { ...next, revision: randomAuthValue() };
        if (!(await storage.replace(key, previous.revision, next))) {
          // A logout/delete wins over the in-flight request. No upsert resurrection.
          await provider.revoke(next.credentials).catch(() => {});
          throw new AuthError("rejected");
        }
        session = next;
      }

      async function rotate() {
        const credentials = await provider.refresh(
          session!.credentials,
          input.signal,
        );
        if (
          credentials.subject !== session!.subject ||
          !Number.isFinite(credentials.accessExpiresAt) ||
          credentials.accessExpiresAt <= now()
        )
          throw new AuthError("rejected");
        // MUST commit before UserInfo. Transient failures must not discard a rotated refresh token.
        await checkpoint({
          ...session!,
          credentials,
          expiresAt: Math.min(
            session!.expiresAt,
            credentials.refreshExpiresAt ?? Infinity,
          ),
        });
        rotated = true;
      }

      try {
        if (
          session.credentials.accessExpiresAt <=
          now() + policy.refreshLeewayMs
        ) {
          if (session.credentials.refreshToken) await rotate();
          else if (session.credentials.accessExpiresAt <= now())
            throw new AuthError("rejected");
        }
        if (
          input.fresh ||
          rotated ||
          session.verifiedAt + policy.identityMaxAgeMs <= now()
        ) {
          let profile;
          try {
            profile = await provider.identity(
              session.credentials,
              input.signal,
            );
          } catch (error) {
            if (
              !(error instanceof AuthError) ||
              error.code !== "rejected" ||
              rotated ||
              !session.credentials.refreshToken
            )
              throw error;
            await rotate();
            profile = await provider.identity(
              session.credentials,
              input.signal,
            );
          }
          if (profile.subject !== session.subject)
            throw new AuthError("rejected");
          const user = await identity.synchronize(profile, session.user);
          if (!identity.allowed(user)) throw new AuthError("rejected");
          await checkpoint({ ...session, user, verifiedAt: now() });
        }
        // A back-channel logout may run outside this key's refresh lock.
        const current = await storage.read(key);
        if (
          !current ||
          current.revision !== session.revision ||
          session.expiresAt <= now() ||
          session.credentials.accessExpiresAt <= now() ||
          (await options.revocation.isRevoked({
            subject: session.subject,
            sid: session.sid,
            issuedAt: session.createdAt,
            now: now(),
          }))
        )
          return null;
        return publicSession(session);
      } catch (error) {
        if (error instanceof AuthError && error.code === "rejected") {
          await storage.remove(key, session.revision);
          return null;
        }
        if (error instanceof AuthError) throw error;
        throw new AuthError("unavailable");
      }
    });
  }

  async function logout(handle: string, signal?: AbortSignal) {
    if (!validHandle(handle)) return { remoteRevoked: true };
    const key = await fingerprintAuthValue(handle);
    // Delete FIRST. An unavailable provider must never leave the local session valid.
    const previous = await storage.remove(key);
    if (!previous || previous.binding !== provider.binding)
      return { remoteRevoked: true };
    try {
      await provider.revoke(previous.credentials, signal);
      return { remoteRevoked: true };
    } catch {
      return { remoteRevoked: false };
    }
  }

  async function safe<Result>(
    operation: () => Promise<Result>,
  ): Promise<Result> {
    try {
      return await operation();
    } catch (error) {
      if (error instanceof AuthError) throw error;
      throw new AuthError("unavailable");
    }
  }
  return {
    create: (login: VerifiedLogin) => safe(() => create(login)),
    get: (handle: string, input?: { fresh?: boolean; signal?: AbortSignal }) =>
      safe(() => get(handle, input)),
    logout: (handle: string, signal?: AbortSignal) =>
      safe(() => logout(handle, signal)),
  };
}
