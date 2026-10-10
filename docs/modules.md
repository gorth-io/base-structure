# Shared application infrastructure

These modules extract eight reusable mechanisms from the Gorth desktop/web
applications. Applications have **not** been migrated. Publish this package,
update consumers, then replace app implementations deliberately. Existing auth
APIs remain compatible. No new dependency, configured client, listener, database,
environment read, secret, UI or application policy is introduced.

| Mechanism                              | Public entry                           | API                                                                               |
| -------------------------------------- | -------------------------------------- | --------------------------------------------------------------------------------- |
| Session-bound token transport          | `@gorth/structure/modules/auth/server` | `createSessionBoundTransport`                                                     |
| Axios HTTP/Response adapter            | `@gorth/structure/modules/http`        | `createFetcher`, `toWebResponse`                                                  |
| Caller request/validation/error core   | `@gorth/structure/modules/http`        | `createCaller`, `CallerError`, `normalizeCallerError`                             |
| Coordinated refresh/retry              | `@gorth/structure/modules/auth/client` | `createAuthRetry`                                                                 |
| OIDC discovery/local JWKS snapshots    | `@gorth/structure/modules/auth/server` | `createOidcDiscovery`                                                             |
| Authoritative credential access        | `@gorth/structure/modules/auth/server` | `createSessionService(...).credentials`                                           |
| BFF HMAC signing/verification          | `@gorth/structure/modules/auth/server` | `createBffSigner`, `createBffVerifier`                                            |
| Desktop RPC and accelerator validation | `@gorth/structure/modules/desktop`     | `createDesktopRpcHandler`, `createDesktopRpcTransport`, `createShortcutValidator` |

## HTTP and caller

```ts
import {
  createFetcher,
  createCaller,
  toWebResponse,
} from "@gorth/structure/modules/http";

const fetcher = createFetcher(applicationAxiosInstance);
const { caller, http, reset, dispose } = createCaller({
  client: applicationAxiosInstance,
  refresh: refreshApplicationSession,
  notify: applicationNotificationAdapter,
  mapError: sanitizeTrustedEndpointError,
});

const data = await http.get("/user", { schema: publicUserSchema, signal });
const upstream = await fetcher({
  url: trustedUpstreamUrl,
  method: "GET",
  redirect: "manual",
});
const response = toWebResponse(upstream);
```

The app creates its Axios instance and selects its runtime adapter. In Electron
renderer, preserve the existing `xhr` selection; do not change Chromium networking
or QUIC settings as part of this migration. No `fetch` adapter is forced.
Browser calls remain same-origin; upstream URLs, cookies, headers, API keys and
destination allowlists stay in server composition. `baseURL: null` explicitly
bypasses an instance default. Cancelled requests do not notify.

`caller` supports request bodies/query, response handlers, Zod validation,
`unwrapData`, success/error callbacks, optional notifications and HTTP verb
helpers. TanStack Query hooks, React state and toast components remain UI adapters,
not dependencies of this package. Queries can use `queryFn: ({ signal }) =>
caller({ ...request, signal })`; mutation hooks can use `http.post` etc. This is a
request-core extraction, **not** a drop-in replacement for app-local React hooks.

Read requests may retry once after a 401. Mutations must opt into `retryUnsafe`
only when the endpoint authenticates before writing or uses idempotency keys.
Never replay a consumed stream/upload body. Auth routes do not retry by default.
Use `reset()` on logout/account change and `dispose()` when tearing down a client.
Neither function restores a session from tokens.

Errors are sanitized by default: no raw Axios cause, request/config, response
body, private message or credentials escape. `mapError` receives response data
only so the app can deliberately project a safe message/code. Do not attach the
raw payload as details. Notifications are supplied callbacks, not imports of UI.

`toWebResponse` preserves JSON `null`, arrays of `Set-Cookie`, status and `Location`.
Use `emptyBody: true` for HEAD/explicitly empty responses. 204/205/304 always have
no body. Encoding/length/hop-by-hop headers are removed because Axios may have
decompressed/reserialized the body. Node streams require an app-supplied `mapBody`
conversion; web streams, blobs, array buffers and typed-array slices are supported.
Server redirect policy uses `maxRedirects: 0`; browser XHR cannot implement a
manual-redirect security boundary, so keep OAuth transport on server/main.

## Refresh coordination

```ts
import { createAuthRetry } from "@gorth/structure/modules/auth/client";
const retry = createAuthRetry({
  refresh: refreshApplicationSession,
  getStatus,
});
await retry.withAuthRetry(request, { signal, enabled: true });
```

A factory owns one refresh flight. Each request retries at most once, with its
original error retained if refresh fails. Aborting one waiter does not cancel
another request's refresh. Reset invalidates late refresh results; app logout and
account switching must call it. SSO itself has no external refresh: omit the
refresh adapter instead of forcing an app-client refresh policy onto Better Auth.

## Discovery and session binding

```ts
import {
  createOidcDiscovery,
  createSessionBoundTransport,
  createOAuthProvider,
} from "@gorth/structure/modules/auth/server";
const discovery = createOidcDiscovery({
  issuer,
  endpointOrigins,
  transport: boundedAuthTransport,
  allowedPath: trustedAuthEndpointPath,
  allowLoopbackHttp,
});
const transport = createSessionBoundTransport(boundedAuthTransport, {
  issuer,
  clientId,
  tokenUrl,
  revocationUrl,
  endpointOrigins,
  allowLoopbackHttp,
  key: discovery.currentVerificationKey,
});
const provider = createOAuthProvider({
  config: applicationOAuthConfig,
  transport,
  getVerificationKey: discovery.getVerificationKey,
  loginStorage: applicationVerificationStorage,
});
```

The app still supplies explicit OAuth configuration, exact endpoint origins and a
transport with bounded timeout/body sizes, disabled redirects/cache and safe
errors. Discovery verifies exact issuer, endpoint URL policy, public asymmetric
JWKS keys, and builds a **local** resolver before token consumption. Cache defaults
to five minutes. `getVerificationKey({ force: true })` reloads for planned key
rotation; `invalidate()` prevents an old flight from publishing into a new cache.
An expired cache is not a network-outage fallback. A token verification operation
uses its prepared key snapshot without further networking. After an unknown `kid`,
reload for the next operation; do not re-exchange an already consumed code/token.

The optional transport wrapper requires a signed, bounded `sid` in successful
token responses and best-effort revokes a rejected grant's new refresh token.
Core OAuth verification still checks nonce, subject, issuer/audience and hashes.
This is interactive app policy, not a universal requirement on every OAuth grant.
Confidential clients supply `revokeRejectedGrant` rather than storing authentication
configuration in this package. Public-client fallback uses `client_id` only.

## Credential access and logout

`sessions.credentials(handle, { fresh, signal })` returns the validated user,
subject, sid, expiry and credentials **only to server/Electron main code**. It runs
the same single locked validation/refresh/checkpoint/revocation path as `get`.
It is not a second unprotected storage read. Do not serialize its output over HTTP,
IPC, browser state or logs. `sessions.get` still returns public session data only.

`sessions.logout` retains app-local semantics: delete first, attempt token
revocation, never create a central sid revocation marker or navigate to SSO.
Verified back-channel logout uses `createLogoutVerifier` and the supplied atomic
revocation store. Any app-specific broader logout policy remains app composition.

## BFF signature

```ts
import {
  createBffSigner,
  createBffVerifier,
} from "@gorth/structure/modules/auth/server";
const sign = createBffSigner({
  context: protocolNamespace,
  key: readSigningKey,
});
const verify = createBffVerifier({
  context: protocolNamespace,
  key: readSigningKey,
  proof: persistentProofStorage,
});
const headers = await sign("/internal/auth/read", serializedBody);
await verify(internalRequest, serializedBody);
```

Both sides use a server-only app-supplied key of at least 32 bytes. No key is
created, read from env or persisted by the module. Web Crypto HMAC-SHA256 binds
namespace, POST method, canonical path **and query**, timestamp, random nonce and
exact body hash. Defaults: 30-second skew window and 1 MiB body limit.
Replay reservation is atomic through `ProofStorage.consume`, only after signature
verification. Its TTL covers future-dated proofs too. A process-local Map is only
appropriate in test fixtures, not shared deployment protection. The existing Chat
signature layout remains compatible for query-free targets with the same context
and key. Proof keys preserve Chat's existing `bff:SHA256(nonce)` contract, so live
replay receipts remain effective while migrating the verifier.

## Desktop RPC and shortcuts

```ts
import {
  createDesktopRpcHandler,
  createDesktopRpcTransport,
  createShortcutValidator,
} from "@gorth/structure/modules/desktop";
const handlePacket = createDesktopRpcHandler({
  handle: applicationRouterFetchHandler,
});
const rpcFetch = createDesktopRpcTransport({ request: trustedPreloadRequest });
const validateShortcut = createShortcutValidator({
  isMac,
  reserved: appReservedAccelerators,
});
```

RPC validates a strict packet, exact synthetic origin, method/procedure path,
URL/body/response limits and cancellation. Main supplies a handler wrapping tRPC
`fetchRequestHandler`, while renderer supplies preload transport to `httpLink`.
No tRPC dependency, actual network, Electron singleton or configured router is
introduced. The app must still verify IPC sender/window/mainFrame identity and
keep remote web contents away from its preload API. AbortSignal is forwarded and
waiting cancels promptly and late results are rejected; transport adapters own
underlying operation cancellation.

Shortcuts normalize accelerators, platform-equivalent modifiers, duplicate
assignments and app-injected reserved bindings. Definition lists, Electron menu
registration, persistence, actions and UI stay in the app.

## Better Auth and Neon Auth session adapters

The token-free client store is provider-independent. The server OAuth/session
engine is **not** a replacement for self-hosted Better Auth or managed Neon Auth.
Keep their SDK responsible for credentials, verification, password reset, OTP,
session cookies, provider events and session renewal. Do not create a second
OAuth credential store merely to wrap an existing SDK session.

```ts
import {
  createAuthClient,
  createSessionAuthAdapter,
} from "@gorth/structure/modules/auth/client";

// applicationAuthSdk is configured by the app (Better Auth or Neon SDK).
const adapter = createSessionAuthAdapter({
  getSession: (signal) =>
    applicationAuthSdk.getSession({
      fetchOptions: { signal },
    }),
  signOut: (signal) =>
    applicationAuthSdk.signOut({
      fetchOptions: { signal },
    }),
  mapUser: (user) => ({ id: user.id, name: user.name, email: user.email }),
  login: applicationLoginAction,
});
const state = createAuthClient(adapter);
await state.load();
```

The adapter accepts `{ data, error }` results with
`data: { user, session: { expiresAt } }`. Expiry accepts a Date, ISO date string,
or epoch **milliseconds**, never seconds. Different SDK result shapes must be
normalized by the app's callbacks. `mapUser` must explicitly select public fields;
SDK session tokens and unselected metadata are never copied into the snapshot.
Errors fail closed, including sign-out failures, and are sanitized. Optional
`errorCode` classifies errors into safe Structure codes without exposing messages.
`now` is injectable; an expired session becomes null; invalid expiry is rejected.
Callbacks receive an AbortSignal; SDK calls that ignore cancellation cannot
publish a late snapshot after cancellation.

`applicationLoginAction` owns forms/passwords or navigation and checks SDK errors.
The store's login action takes navigation/prompt input, **not credentials**. It
does not implement password/OTP operations. Use SDK methods for these; call
`state.load()` after successful authentication. Prefer the provider's native
`useSession()` when it already meets the app's needs; this store is optional.
Provider cross-tab/account events should trigger `load()` using app-owned
subscriptions, which must be cleaned up by the app. Do not run conflicting
polling, token refresh or independent session caches in both layers.

Use Neon’s own `@neondatabase/auth` SDK with this adapter, not Structure's
`cores/auth/client` re-export as a substitute for Neon's integrations/plugins.
This is a structural SDK adapter tested with fixtures, not a claim that every
Neon version/plugin has been tested against a live managed instance.

References: [Better Auth client](https://better-auth.com/docs/concepts/client),
[Neon SDK differences](https://github.com/neondatabase/neon-js/blob/main/packages/auth/neon-auth_vs_better-auth.md).

## Release checks

### TypeScript module conventions and shared auth optimizations

Module contracts are declared once in `src/utils/interface.ts`. Public type
re-exports at the original HTTP/auth/desktop/Supabase paths remain compatible.
Internal imports use `@/` and asynchronous control flow uses `async/await` with
`try/catch/finally`, not Promise `.then/.catch/.finally` chains. Pure projection,
serialization and formatting helpers live in `src/utils/formatter.ts`. Public
utility paths are `@gorth/structure/utils/interface` (types only) and
`@gorth/structure/utils/formatter`. The utility runtime imports no framework,
database driver, provider SDK, environment, secret or configured service.

`createAuthFreshnessPolicy(overrides, now)` is exported by both auth client and
server entries. Its returned function accepts `verifiedAt`, `accessExpiresAt`
and optional `fresh`, and returns `expired`, `refresh`, `verifyIdentity`. The
default identity freshness window is 120 seconds; overrides and the clock are
app supplied. Future verification timestamps require revalidation; non-finite
or negative timestamps are rejected. This helper does **not** authorize users,
read storage, cache identity, rotate tokens or replace revocation/local-role
checks. The session engine uses it for its existing refresh/verification decisions.

Client login adapters may return `{ status: "redirecting" }` after starting a
web navigation. The store stays loading/busy and performs no extra session read.
Return `{ status: "completed" }` after an SDK/Electron callback to read the new
public session. Existing `Promise<void>` adapters keep the completed-login
behavior. SDK session adapters forward this outcome unchanged. Apps are not
automatically migrated; their navigation adapters must opt into this result.

Discovery cache reads and refresh flights remain shared per factory. Use
`getVerificationKey()` for normal reads, not `force: true` on every operation.
After an actual `ERR_JWKS_NO_MATCHING_KEY`, the app can call
`refreshForUnknownKey(kid, { signal })`. Known IDs do not reload, concurrent
reloads coalesce, and unknown IDs are throttled by `rotationCooldownMs` (default
30 seconds). Missing IDs remain rejected, and failures never return expired
fallback keys. `force: true` remains an explicit operator escape hatch.
Prepared resolvers remain immutable snapshots; the helper does not transparently
fetch during signature verification or replay an OAuth code/refresh grant.
Prepare keys before exchanging/rotating credentials and checkpoint rotated
credentials durably. Providers should publish overlapping keys before rotation.

Formatters perform transformations only, not trust decisions. In particular,
`formatOAuthIdentity` requires validated provider claims, OAuth URL helpers
require validated configuration/transactions, and `formatSessionCredentials`
is for trusted server/main code only. Never serialize credentials into an app
response, client state or renderer IPC. App-only logout, event revocation, API
audience/scopes and local permissions retain their separate responsibilities.

The standardization regression test scans the entire `src/modules` tree for
contract declarations, relative imports, Promise chains and environment access.
Existing runtime tests cover OAuth validation, durable refresh checkpoints,
revocation fences, app-only logout and cancellation. Built ESM/CJS/export and
browser-safe graph checks also cover the shared utility exports.

### Verification commands

Run `pnpm verify` before pushing a release commit/tag. It checks source/types,
runtime tests, builds ESM/CommonJS/declarations, then tests the public built
exports and browser-safe import graph. `prepack` runs the same checks so a failed
verification stops packaging. No new SDK/dependency or app configuration is added.

GitHub dependencies require a committed release and consumer lockfile refresh.
`private: true` permits the current GitHub distribution but intentionally blocks
npm registry publication. Do not change it unless moving to a registry.
Publish the added source/tests/docs, not only package.json; dist is build-generated.
Pin production consumers to a tested tag/commit rather than a moving branch.

## App migration

Do not replace app runtime/config/store files wholesale. Wire the new factories
from existing composition, preserve ciphertext formats and DB semantics, then
run each app's auth/network/IPC tests. These additions do not migrate the custom
website JWE format or change Better Auth configuration.

Package verification: `pnpm test:types`, `pnpm test`, `pnpm build`,
`pnpm test:exports`. Built public entrypoints are tested through ESM and CommonJS,
and browser-safe dependency graphs are checked independently of server helpers.
