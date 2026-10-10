import type { AuthError } from "@/modules/auth/interface";
import type { CallerError } from "@/modules/http/error";
import type { CookieMethodsServer } from "@supabase/ssr";
import type {
  REALTIME_SUBSCRIBE_STATES,
  RealtimeChannel,
  RealtimeChannelOptions,
  SupabaseClient,
} from "@supabase/supabase-js";
import type {
  AxiosInstance,
  AxiosRequestConfig,
  AxiosResponse,
  Method,
} from "axios";
import type {
  ResourceRequestInput,
  VerifyAccessTokenRequestOptions,
} from "better-auth/oauth2";
import type { JWTPayload, JWTVerifyGetKey } from "jose";
import type { ZodType } from "zod";

export interface AuthClientAdapter<User> {
  /** Same-origin app endpoint on web; trusted preload IPC on desktop. No OAuth tokens. */
  read(signal: AbortSignal): Promise<PublicSession<User> | null>;
  login(
    input: {
      returnTo: string;
      prompt?: "login" | "create" | "consent" | "select_account";
    },
    signal: AbortSignal,
  ): Promise<AuthLoginResult>;
  logout(signal: AbortSignal): Promise<void>;
}

export interface AuthClientState<User> {
  status: "loading" | "authenticated" | "anonymous" | "error";
  session: PublicSession<User> | null;
  busy: boolean;
  error: Exclude<AuthErrorCode, "invalid_configuration"> | null;
}

/** Existing void adapters are completed logins. Navigation adapters report redirecting. */
export type AuthLoginResult = void | { status: "completed" | "redirecting" };

export interface AuthLoginInput {
  returnTo?: string;
  prompt?: "login" | "create" | "consent" | "select_account";
}

export interface AuthReadInput {
  fresh?: boolean;
  signal?: AbortSignal;
}

export interface AuthCookieInput {
  secure: boolean;
  maxAgeSeconds: number;
  path?: string;
}

export interface AuthEndpointPolicy {
  origins?: readonly string[];
  allowLoopbackHttp?: boolean;
  allowedPath?(url: URL): boolean;
}

export interface OAuthIdentityClaims {
  sub: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
  preferred_username?: string | null;
  picture?: string | null;
}

export type DatabaseSchema<T> = string & keyof Omit<T, "__InternalSupabase">;
export type DefaultSchema<T> =
  "public" extends DatabaseSchema<T> ? "public" : DatabaseSchema<T>;

export interface AuthRetryOptions {
  /** App session read/refresh or trusted IPC; never return OAuth tokens. */
  refresh(signal: AbortSignal): Promise<boolean>;
  getStatus(error: unknown): number | undefined;
}

export interface AuthRetryInput {
  enabled?: boolean;
  signal?: AbortSignal;
}

/** SDK envelopes are unwrapped here, never stored in the public client snapshot. */
export interface SessionSdkResult<Data> {
  data?: Data | null;
  error?: unknown;
}

export interface SessionSdkSession<User> {
  user: User;
  session: { expiresAt: Date | string | number };
}

export interface SessionAuthAdapterOptions<ProviderUser, User> {
  getSession(
    signal: AbortSignal,
  ): Promise<SessionSdkResult<SessionSdkSession<ProviderUser>>>;
  signOut(signal: AbortSignal): Promise<SessionSdkResult<unknown>>;
  /** Select public fields explicitly; do not spread provider users containing private metadata. */
  mapUser(user: ProviderUser): User;
  /** App owns credentials/forms/navigation and the SDK-specific login call. */
  login: AuthClientAdapter<User>["login"];
  /** Accept ONLY explicit safe auth codes, not provider messages/response bodies. */
  errorCode?(error: unknown): AuthError["code"];
  now?: () => number;
}

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

/** Public identity projection. Provider roles never overwrite application roles. */
export interface AuthIdentity {
  subject: string;
  name?: string;
  email?: string;
  emailVerified?: boolean;
  username?: string | null;
  image?: string | null;
}

export interface PublicSession<User> {
  user: User;
  expiresAt: number;
}

export interface AuthPolicy {
  sessionMaxAgeMs: number;
  transactionMaxAgeMs: number;
  identityMaxAgeMs: number;
  refreshLeewayMs: number;
  clockToleranceSeconds: number;
  logoutMaxAgeSeconds: number;
  /** Cover the longest accepted access/app-session lifetime, not logout JWT expiry. */
  revocationRetentionMs: number;
}

export type AuthErrorCode =
  | "invalid_configuration"
  | "rejected"
  | "forbidden"
  | "unavailable"
  | "cancelled";

export interface BffSignatureOptions {
  /** Protocol/app namespace prevents signatures being replayed in another protocol. */
  context: string;
  /** Key manager belongs to the app. Never import these server helpers into browser UI. */
  key(): Uint8Array | Promise<Uint8Array>;
  now?: () => number;
  maxBodyBytes?: number;
}

export interface BffVerifierOptions extends BffSignatureOptions {
  proof: ProofStorage;
  maxAgeMs?: number;
}

export interface OidcMetadata {
  issuer: string;
  jwks_uri: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  userinfo_endpoint?: string;
  revocation_endpoint?: string;
  end_session_endpoint?: string;
}

export interface OidcDiscoveryOptions {
  issuer: string;
  endpointOrigins: readonly string[];
  allowedPath?(url: URL): boolean;
  allowLoopbackHttp?: boolean;
  transport: AuthTransport;
  cacheMaxAgeMs?: number;
  /** Bounds reloads requested after an unknown key ID. Explicit force remains an operator action. */
  rotationCooldownMs?: number;
  now?: () => number;
}

export interface OidcLoadInput {
  force?: boolean;
  signal?: AbortSignal;
}

export interface OidcSnapshot {
  metadata: Readonly<OidcMetadata>;
  key: JWTVerifyGetKey;
  keyIds: ReadonlySet<string>;
  expiresAt: number;
}

export interface AuthFreshnessInput {
  verifiedAt: number;
  accessExpiresAt: number;
  fresh?: boolean;
}

export interface AuthFreshness {
  expired: boolean;
  refresh: boolean;
  verifyIdentity: boolean;
}

export interface AuthCipherOptions {
  key: Uint8Array;
  audience: string;
  now?: () => number;
}

export interface DesktopLoginOptions {
  provider: DesktopLoginProvider;
  adapter: DesktopLoginAdapter;
  now?: () => number;
}

export interface DesktopLoginInput extends AuthLoginInput {
  signal?: AbortSignal;
}

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

export interface LogoutVerifierOptions {
  issuer: string;
  clientId: string;
  getVerificationKey(): Promise<JWTVerifyGetKey>;
  storage: LogoutStorage;
  algorithms?: readonly ("RS256" | "ES256" | "EdDSA")[];
  requireSid?: boolean;
  policy?: Partial<AuthPolicy>;
  now?: () => number;
}

export interface ResourceAuthOptions {
  /** Explicit issuer/audience, trusted JWKS URL or confidential introspection configuration. */
  verification: Omit<VerifyAccessTokenRequestOptions, "dpop">;
  proof: ProofStorage;
  revocation: LogoutStorage;
  /** UserInfo/introspection supplied by the app. Reject inactive identity, throw unavailable on outages. */
  verifyActive(
    claims: JWTPayload,
    request: ResourceRequestInput,
  ): Promise<void>;
  onlineVerification: "always" | "sensitive";
  /** Defaults true. A provider without sid must use onlineVerification: always. */
  requireSid?: boolean;
  allowLoopbackHttp?: boolean;
  policy?: Partial<AuthPolicy>;
  now?: () => number;
}

export interface SessionBoundTransportOptions {
  issuer: string;
  clientId: string;
  tokenUrl: string;
  revocationUrl: string;
  endpointOrigins: readonly string[];
  allowLoopbackHttp?: boolean;
  /** Must be a prepared local resolver, obtained BEFORE token rotation. */
  key(): JWTVerifyGetKey | undefined;
  algorithms?: readonly ("RS256" | "ES256" | "EdDSA")[];
  clockToleranceSeconds?: number;
  now?: () => number;
  /** Confidential clients can supply their own authenticated revocation adapter. */
  revokeRejectedGrant?(
    refreshToken: string,
    signal?: AbortSignal,
  ): Promise<void>;
}

export interface SessionServiceOptions<User> {
  provider: OAuthProvider;
  storage: SessionStorage<User>;
  revocation: LogoutStorage;
  identity: IdentityAdapter<User>;
  policy?: Partial<AuthPolicy>;
  now?: () => number;
}

export type CommonCookieMethods = Pick<
  CookieMethodsServer,
  "getAll" | "setAll"
>;

export type SupabaseAnyClient = SupabaseClient<any, any, any>;

export type RealtimeUtils = {
  createChannel: (
    topic: string,
    options?: RealtimeChannelOptions,
  ) => RealtimeChannel;
  subscribe: (
    channel: RealtimeChannel,
    callback?: (status: REALTIME_SUBSCRIBE_STATES, error?: Error) => void,
  ) => Promise<REALTIME_SUBSCRIBE_STATES>;
  removeChannel: (
    channel: RealtimeChannel,
  ) => Promise<"ok" | "timed out" | "error">;
  removeAllChannels: () => Promise<("ok" | "timed out" | "error")[]>;
};

export type UploadInput = {
  bucket: string;
  path: string;
  fileBody: File | Blob | ArrayBuffer | ArrayBufferView | string;
  options?: Record<string, unknown>;
};

export type UploadUtils = {
  upload: (input: UploadInput) => Promise<any>;
  upsert: (input: UploadInput) => Promise<any>;
  remove: (bucket: string, paths: string[]) => Promise<any>;
  getPublicUrl: (
    bucket: string,
    path: string,
  ) => { data: { publicUrl: string } };
  createSignedUrl: (
    bucket: string,
    path: string,
    expiresIn: number,
  ) => Promise<any>;
};

export interface DesktopRpcRequest {
  url: string;
  method: "GET" | "POST";
  body?: string;
}

export interface DesktopRpcResponse {
  status: number;
  body: string;
}

export interface DesktopRpcPolicy {
  origin?: string;
  endpoint?: string;
  maxUrlLength?: number;
  maxBodyBytes?: number;
  maxResponseBytes?: number;
}

export interface DesktopRpcHandlerOptions extends DesktopRpcPolicy {
  handle(request: Request): Promise<Response>;
}

export interface DesktopRpcTransportOptions extends DesktopRpcPolicy {
  request(
    input: DesktopRpcRequest,
    signal?: AbortSignal,
  ): Promise<DesktopRpcResponse>;
}

export interface ShortcutDefinition {
  id: string;
  label: string;
  defaultAccelerator: string;
}

export interface Shortcut extends ShortcutDefinition {
  accelerator: string;
}

export interface ShortcutPolicy {
  isMac: boolean;
  /** Reserved bindings/actions belong to each app, not this package. */
  reserved: readonly string[];
}

export type CallerResponseHandler<Data> =
  | "json"
  | "text"
  | "blob"
  | "arrayBuffer"
  | "stream"
  | "content-type"
  | ((response: AxiosResponse<unknown>) => Data | Promise<Data>);

export interface CallerToastOptions<Data> {
  success?: string | ((data: Data) => string);
  error?: string | ((error: CallerError) => string);
}

export interface CallerRequestOptions<
  Data = unknown,
  Body = unknown,
  Params = Record<string, unknown>,
> extends Omit<
  AxiosRequestConfig<Body>,
  "url" | "method" | "data" | "params" | "auth" | "baseURL" | "signal"
> {
  url: string;
  method?: Method;
  body?: Body;
  params?: Params;
  query?: Params;
  baseURL?: string | null;
  signal?: AbortSignal;
  auth?: boolean;
  unwrapData?: boolean;
  schema?: ZodType<Data>;
  responseHandler?: CallerResponseHandler<Data>;
  cache?: RequestCache;
  credentials?: RequestCredentials;
  redirect?: RequestRedirect;
  /** Mutations must explicitly opt into replay after a 401 (idempotent/auth-before-write). */
  retryUnsafe?: boolean;
  toast?: boolean | CallerToastOptions<Data>;
  onSuccess?(data: Data): void | Promise<void>;
  onError?(error: CallerError): void | Promise<void>;
}

export interface CallerOptions {
  client: AxiosInstance;
  refresh?(signal: AbortSignal): Promise<boolean>;
  /** App supplies UI notification implementation. No UI dependency in this module. */
  notify?(kind: "success" | "error", message: string): void;
  /** Explicit sanitizer for trusted endpoint errors; never receive Axios config. */
  mapError?(error: CallerError, responseData: unknown): CallerError;
  canRetry?(url: string): boolean;
}

export type CallerMethodOptions<Data, Body, Params> = Omit<
  CallerRequestOptions<Data, Body, Params>,
  "url" | "method" | "body"
>;

export interface CallerErrorOptions {
  status?: number;
  code?: string;
  /** Opt-in safe endpoint metadata only; never include Axios config/request/cause. */
  details?: unknown;
}

export interface FetcherOptions<
  Body = unknown,
  Params = Record<string, unknown>,
> extends Omit<
  AxiosRequestConfig<Body>,
  "url" | "method" | "data" | "params" | "withCredentials"
> {
  url: string | URL;
  method: Method;
  body?: Body;
  params?: Params;
  cache?: RequestCache;
  credentials?: RequestCredentials;
  redirect?: RequestRedirect;
}

export interface WebResponseOptions {
  /** Explicitly empty a successful body, as distinct from JSON null. */
  emptyBody?: boolean;
  /** Node streams need an app/runtime-specific conversion. */
  mapBody?(data: unknown): BodyInit | null;
}
