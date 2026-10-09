import { createSessionService } from "../src/modules/auth/server/session";
import type {
  LogoutStorage,
  OAuthProvider,
  SessionStorage,
  StoredSession,
  VerifiedLogin,
  VerifiedLogout,
} from "../src/modules/auth/server/interface";

export interface TestUser {
  id: string;
  role: string;
  active: boolean;
  name?: string;
}

/** Test-only adapter. Production adapters MUST implement the durable contracts in docs/auth.md. */
export function sessionFixture() {
  let time = Date.now();
  const now = () => time;
  const records = new Map<string, StoredSession<TestUser>>();
  const receipts = new Map<string, VerifiedLogout>();
  const locks = new Map<string, Promise<void>>();
  let refreshes = 0;
  let localActive = true;
  const matches = (
    session: { subject: string; sid?: string; issuedAt: number },
    logout: VerifiedLogout,
  ) =>
    (!logout.sid || logout.sid === session.sid) &&
    (!logout.subject || logout.subject === session.subject) &&
    (!!logout.sid ||
      Math.floor(session.issuedAt / 1000) <=
        Math.floor(logout.issuedAt / 1000));
  const revocation: LogoutStorage = {
    async isRevoked(input) {
      return [...receipts.values()].some(
        (logout) => logout.revokeUntil > time && matches(input, logout),
      );
    },
    async apply(logout) {
      if (receipts.has(logout.jti)) return false;
      receipts.set(logout.jti, logout);
      for (const [key, session] of records)
        if (matches({ ...session, issuedAt: session.createdAt }, logout))
          records.delete(key);
      return true;
    },
  };
  const storage: SessionStorage<TestUser> = {
    async withLock(key, operation) {
      const previous = locks.get(key) ?? Promise.resolve();
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      const tail = previous.then(() => gate);
      locks.set(key, tail);
      await previous;
      try {
        return await operation();
      } finally {
        release();
        if (locks.get(key) === tail) locks.delete(key);
      }
    },
    async read(key) {
      return records.has(key) ? structuredClone(records.get(key)!) : null;
    },
    async insert(session) {
      if (
        records.has(session.key) ||
        (await revocation.isRevoked({
          ...session,
          issuedAt: session.createdAt,
          now: time,
        }))
      )
        return false;
      records.set(session.key, structuredClone(session));
      return true;
    },
    async replace(key, revision, next) {
      if (
        records.get(key)?.revision !== revision ||
        (await revocation.isRevoked({
          ...next,
          issuedAt: next.createdAt,
          now: time,
        }))
      )
        return false;
      records.set(key, structuredClone(next));
      return true;
    },
    async remove(key, revision) {
      const previous = records.get(key);
      if (!previous || (revision && previous.revision !== revision))
        return null;
      records.delete(key);
      return structuredClone(previous);
    },
  };
  const provider: OAuthProvider = {
    binding: "issuer|client",
    async refresh(previous) {
      refreshes++;
      return {
        ...previous,
        accessToken: "access-new",
        refreshToken: "refresh-new",
        accessExpiresAt: time + 3_600_000,
      };
    },
    async identity(credentials) {
      return { subject: credentials.subject, name: "Updated" };
    },
    async revoke() {},
  };
  const login: VerifiedLogin = {
    returnTo: "/",
    sid: "sid-a",
    identity: { subject: "subject-a", name: "Old" },
    credentials: {
      subject: "subject-a",
      nonce: "nonce",
      accessToken: "access-old",
      refreshToken: "refresh-old",
      accessExpiresAt: time + 10_000,
    },
  };
  const service = () =>
    createSessionService<TestUser>({
      provider,
      storage,
      revocation,
      now,
      identity: {
        async synchronize(identity, previous) {
          return {
            id: identity.subject,
            name: identity.name,
            role: previous?.role ?? "editor",
            active: localActive,
          };
        },
        async read(user) {
          return { ...user, active: localActive };
        },
        allowed(user) {
          return user.active;
        },
      },
    });
  return {
    provider,
    storage,
    revocation,
    records,
    login,
    service,
    now,
    advance: (ms: number) => {
      time += ms;
    },
    refreshes: () => refreshes,
    disable: () => {
      localActive = false;
    },
  };
}

export function deferred<Value>() {
  let resolve!: (value: Value) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<Value>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
