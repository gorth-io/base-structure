import type { JWTVerifyGetKey } from "jose";
import type { AuthIdentity, AuthPolicy } from "../interface";

export interface OAuthConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  /** Only needed for explicitly requested provider-wide logout. */
  postLogoutRedirectUri?: string;
  endpoints: {
    authorization: string;
    token: string;
    userinfo: string;
    revocation: string;
    endSession?: string;
  };
  /** Exact trusted origins, including a separate SSO API origin if applicable. */
  endpointOrigins: readonly string[];
  scopes: readonly string[];
  resources?: readonly string[];
  algorithms?: readonly ("RS256" | "ES256" | "EdDSA")[];
  requireResponseIssuer?: boolean;
  allowLoopbackHttp?: boolean;
}

export interface AuthTransport {
  /** No redirect following, no caching, bounded timeout/response size; never log credentials. */
  request(
    url: string,
    options: {
      method: "GET" | "POST";
      headers: Readonly<Record<string, string>>;
      body?: URLSearchParams;
      signal?: AbortSignal;
    },
  ): Promise<{ status: number; data: unknown }>;
}

export interface LoginTransaction {
  state: string;
  verifier: string;
  nonce: string;
  issuer: string;
  clientId: string;
  redirectUri: string;
  returnTo: string;
  expiresAt: number;
}

export interface LoginStorage {
  /** Persist a hashed state receipt; the transaction itself belongs in an encrypted cookie/vault. */
  reserve(stateHash: string, expiresAt: number): Promise<boolean>;
  /** Atomic delete-if-unexpired across instances. Never a separate read then delete. */
  consume(stateHash: string, now: number): Promise<boolean>;
}

export interface OAuthCredentials {
  accessToken: string;
  refreshToken?: string;
  accessExpiresAt: number;
  refreshExpiresAt?: number;
  subject: string;
  nonce: string;
}

export interface VerifiedLogin {
  identity: AuthIdentity;
  credentials: OAuthCredentials;
  sid?: string;
  returnTo: string;
}

export interface OAuthProvider {
  readonly binding: string;
  identity(
    credentials: OAuthCredentials,
    signal?: AbortSignal,
  ): Promise<AuthIdentity>;
  refresh(
    credentials: OAuthCredentials,
    signal?: AbortSignal,
  ): Promise<OAuthCredentials>;
  revoke(credentials: OAuthCredentials, signal?: AbortSignal): Promise<void>;
}

export interface OAuthOptions {
  config: OAuthConfig;
  transport: AuthTransport;
  /** App supplies a pinned/cacheable JWKS resolver. Called before refresh-token rotation. */
  getVerificationKey(): Promise<JWTVerifyGetKey>;
  loginStorage: LoginStorage;
  policy?: Partial<AuthPolicy>;
  now?: () => number;
}

export interface StoredSession<User> {
  key: string;
  revision: string;
  binding: string;
  user: User;
  subject: string;
  sid?: string;
  credentials: OAuthCredentials;
  createdAt: number;
  expiresAt: number;
  verifiedAt: number;
}

/** Trusted server/main process only. Never serialize over an app endpoint or IPC. */
export interface SessionCredentials<User> {
  user: User;
  subject: string;
  sid?: string;
  credentials: OAuthCredentials;
  expiresAt: number;
}

export interface SessionStorage<User> {
  /** Cross-instance exclusion, including renewal/fencing for distributed leases. */
  withLock<Result>(
    key: string,
    operation: () => Promise<Result>,
  ): Promise<Result>;
  read(key: string): Promise<StoredSession<User> | null>;
  /** Unique insert only, checking active revocation markers atomically. */
  insert(session: StoredSession<User>): Promise<boolean>;
  /** Durable checkpoint before resolving; CAS, never upsert. Check revocation atomically. */
  replace(
    key: string,
    revision: string,
    next: StoredSession<User>,
  ): Promise<boolean>;
  remove(key: string, revision?: string): Promise<StoredSession<User> | null>;
}

export interface IdentityAdapter<User> {
  /** Synchronize identity by stable subject. Preserve local role/status; never accept provider roles. */
  synchronize(identity: AuthIdentity, previous?: User): Promise<User>;
  /** Read current local authorization state on every protected call, not just a cached profile. */
  read(user: User): Promise<User | null>;
  allowed(user: User): boolean;
}

export interface VerifiedLogout {
  jti: string;
  subject?: string;
  sid?: string;
  issuedAt: number;
  receiptExpiresAt: number;
  revokeUntil: number;
}

export interface LogoutStorage {
  /** One transaction: deduplicate jti, persist revocation, invalidate matching sessions.
   * When both sid/sub exist, match BOTH. Subject-only markers apply to sessions
   * created at/before the end of issuedAt's second (JWT iat has second precision).
   * Fence insert/replace to prevent refresh resurrection.
   */
  apply(logout: VerifiedLogout): Promise<boolean>;
  isRevoked(input: {
    subject: string;
    sid?: string;
    issuedAt: number;
    now: number;
  }): Promise<boolean>;
}

export interface ProofStorage {
  /** Atomic insert-if-absent; a live replay key must never be overwritten. */
  consume(key: string, expiresAt: number): Promise<boolean>;
}
