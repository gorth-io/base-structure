import { AuthError } from "@/modules/auth/interface";
import {
  createAuthFreshnessPolicy,
  createAuthPolicy,
} from "@/modules/auth/policy";
import {
  fingerprintAuthValue,
  randomAuthValue,
} from "@/modules/auth/server/crypto";
import type {
  SessionCredentials,
  StoredSession,
  VerifiedLogin,
} from "@/modules/auth/server/interface";
import {
  formatPublicSession,
  formatSessionCredentials,
} from "@/utils/formatter";
import type { AuthReadInput, SessionServiceOptions } from "@/utils/interface";

function validHandle(handle: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(handle);
}

export function createSessionService<User>(
  options: SessionServiceOptions<User>,
) {
  const policy = createAuthPolicy(options.policy);
  const now = options.now ?? Date.now;
  const freshness = createAuthFreshnessPolicy(policy, now);
  const { storage, provider, identity } = options;

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
    return { handle, session: formatPublicSession(session) };
  }

  async function read(
    handle: string,
    input: AuthReadInput = {},
  ): Promise<StoredSession<User> | null> {
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
          try {
            await provider.revoke(next.credentials);
          } catch {
            /* A failed remote revoke cannot resurrect the removed session. */
          }
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
          freshness({
            verifiedAt: session.verifiedAt,
            accessExpiresAt: session.credentials.accessExpiresAt,
          }).refresh
        ) {
          if (session.credentials.refreshToken) await rotate();
          else if (session.credentials.accessExpiresAt <= now())
            throw new AuthError("rejected");
        }
        if (
          rotated ||
          freshness({
            verifiedAt: session.verifiedAt,
            accessExpiresAt: session.credentials.accessExpiresAt,
            fresh: input.fresh,
          }).verifyIdentity
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
        return session;
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
    get: (handle: string, input?: AuthReadInput) =>
      safe(async () => {
        const session = await read(handle, input);
        return session ? formatPublicSession(session) : null;
      }),
    /** Same authoritative locked read/refresh path as get; trusted runtime only. */
    credentials: (
      handle: string,
      input?: AuthReadInput,
    ): Promise<SessionCredentials<User> | null> =>
      safe(async () => {
        const session = await read(handle, input);
        return session ? formatSessionCredentials(session) : null;
      }),
    logout: (handle: string, signal?: AbortSignal) =>
      safe(() => logout(handle, signal)),
  };
}

export type { SessionServiceOptions } from "@/utils/interface";
