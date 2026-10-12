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
import type { BetterAuthOptions } from "better-auth";

export interface AuthCookieInput {
  secure: boolean;
  maxAgeSeconds: number;
  path?: string;
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

/** Public identity projection; provider roles never overwrite local roles. */
export interface AuthIdentity {
  subject: string;
  name?: string;
  email?: string;
  emailVerified?: boolean;
  username?: string | null;
  image?: string | null;
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

/** Validated identity only, never an authorization/session/token cache. */
export interface IdentityCacheOptions<Value> {
  load(credential: string): Promise<Value>;
  /** Inject key derivation for non-token credentials; default is SHA-256. */
  key?(credential: string): Promise<string>;
  maxAgeMs?: number;
  capacity?: number;
  maxPending?: number;
  now?: () => number;
}
export interface IdentityCacheInput {
  fresh?: boolean;
  signal?: AbortSignal;
}
export interface OAuthIdentityValidatorOptions {
  providerId: string;
  /** App-owned additional-field projection. Never match identities by email. */
  subject(
    user: Parameters<
      NonNullable<NonNullable<BetterAuthOptions["user"]>["validateUserInfo"]>
    >[0]["user"],
  ): unknown;
  allowed?(profile: Record<string, unknown>): boolean | Promise<boolean>;
}
export interface AuthSessionBinding {
  id: string;
  userId: string;
  subject: string;
  sid?: string;
  expiresAt: number;
}
export interface SessionGrantGuardOptions {
  /** Authoritative native session read, not a cookie-cache-only result. */
  read(): Promise<AuthSessionBinding | null>;
  /** App verifies persistent revocation and current local permissions. */
  assertAllowed(binding: Readonly<AuthSessionBinding>): Promise<void>;
  now?: () => number;
}
export interface AuthRevocation {
  subject?: string;
  sid?: string;
  issuedAt: number;
  expiresAt: number;
}
export interface AuthRevocationIdentity {
  subject: string;
  sid?: string;
  issuedAt: number;
}
