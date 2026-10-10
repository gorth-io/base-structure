# Shared application authentication

The server OAuth engine standardizes **relying-party** authentication against Gorth SSO. It
does not start another Better Auth authority, read application environment
variables, open a database, start an HTTP listener, mount routes, or import
Next.js/Electron. Existing `cores/auth/*` exports are unchanged.

The implementation targets the installed Better Auth **1.7.7** APIs and JOSE
**6.2.12**. Runtime prerequisites follow the package's ES2024 target and include
Web Crypto (modern Node/Electron main, or a compatible server runtime).

## Entrypoints and ownership

| Public import                           | Runtime                             | Responsibilities                                                                                                                                          |
| --------------------------------------- | ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@gorth/structure/modules/auth/client`  | Web UI / Electron renderer          | Token-free external store, deduplicated session loads, login/logout actions, stale-response fencing                                                       |
| `@gorth/structure/modules/auth/server`  | Next.js server, Hono, Electron main | PKCE, signed OIDC verification, app sessions, refresh coordination, logout/revocation, resource verification, DPoP reservations, authenticated encryption |
| `@gorth/structure/modules/auth/desktop` | Electron main only                  | Loopback callback orchestration, window/navigation cancellation and listener cleanup; delegates OAuth to the shared server engine                         |

The desktop entry exists because listener/window lifecycles differ from an HTTP
callback route. It does **not** implement a second session or token engine.
Never import either trusted-runtime entry into a Client Component or renderer.
Server/desktop entrypoints return credentials for trusted composition; never
serialize those results over HTTP or IPC. Only `PublicSession<User>` belongs in UI.

## Configuration and policy

Pass explicit configuration from the app's existing environment module. No
factory derives endpoints, reads secrets, or falls back to environment variables.
`OAuthConfig` contains the exact issuer, client ID, registered redirect and
optional post-logout redirect, fixed endpoints, exact endpoint origins, scopes and optional
RFC 8707 resource indicators. The issuer may differ from the API endpoint origin,
provided the app explicitly lists the trusted API origin.

`endpoints.endSession` and `postLogoutRedirectUri` are optional as a pair.
Apps with local-only logout should omit both. `sessions.logout()` does not use
either; `provider.logoutUrl()` throws `invalid_configuration` if the pair is
absent. Calling that method is an explicit choice to initiate provider-wide
logout, not the default app logout behavior.

Provider endpoints require HTTPS. `allowLoopbackHttp: true` permits HTTP only on
localhost/127.0.0.1/IPv6 loopback, never arbitrary hosts. This is an explicit local
development/native callback choice, not an automatic production fallback.
Registered callbacks and post-logout targets cannot contain credentials, queries
or fragments. Authorization response `iss` is required by default; explicitly
disable that requirement only for a provider that does not advertise RFC 9207.

This client implements public-client token authentication (`none`), matching the
Gorth app registrations. It does not accept a client secret from a renderer.
Supported ID/logout signing algorithms are RS256, ES256 and EdDSA; token hash
verification for EdDSA requires Ed25519. Symmetric/unsigned tokens are rejected.
Request `offline_access` only when refresh is needed. Only Bearer token responses
are accepted by the OAuth login engine; this is not a DPoP-bound token-issuance
client. The **resource verifier** can receive Bearer and DPoP requests.

`createAuthPolicy()` defaults:

- App-session lifetime: 7 days, absolute (not sliding).
- PKCE transaction lifetime: 120 seconds by default; maximum configurable 10 minutes.
- Identity freshness cache: 120 seconds; `get(handle, { fresh: true })` bypasses it.
- Refresh leeway: 30 seconds; clock tolerance: 5 seconds.
- Logout JWT age/lifetime: maximum 120 seconds.
- Revocation retention: at least the longest accepted app/access-token lifetime
  plus skew, not merely the logout JWT's expiry.

Pass the same policy overrides to related OAuth/session/logout/resource factories.
Financial, security-sensitive and permission-changing operations should request
fresh identity validation. Local user status/permissions remain app-owned;
`IdentityAdapter.read` runs on every app-session lookup, including cache hits.
Provider claims are projected to identity fields only: an SSO role cannot silently
replace the application's local role.

## Trusted-runtime composition

```ts
import {
  createOAuthProvider,
  createSessionService,
  createLogoutVerifier,
  authCookieOptions,
  assertMutationOrigin,
} from "@gorth/structure/modules/auth/server";

// All values and adapters below belong to the consuming application.
const provider = createOAuthProvider({
  config: oauthConfig,
  policy,
  transport: ssoTransport,
  getVerificationKey: prepareLocalJwksResolver,
  loginStorage: verificationStorage,
});
const sessions = createSessionService({
  provider,
  policy,
  storage: sessionStorage,
  revocation: logoutStorage,
  identity: localUserAdapter,
});
const backchannel = createLogoutVerifier({
  issuer: oauthConfig.issuer,
  clientId: oauthConfig.clientId,
  getVerificationKey: prepareLocalJwksResolver,
  storage: logoutStorage,
  policy,
});
```

`AuthTransport.request` is an app-supplied Axios/fetcher adapter. It must refuse
redirects, disable caching, bound time and response size, respect AbortSignal and
avoid logging request configuration, codes or credentials. Non-JSON revoke
success can map to `{ status, data: null }`. Factories translate provider errors
to safe `AuthError` codes; adapters must never expose raw Axios errors to UI.

`getVerificationKey` must **prepare a trusted, locally resolvable JWKS set** before
returning its JOSE resolver. The app owns secure JWKS fetching, caching, key
rotation, endpoint validation and response-size limits. Do not return an unprimed
network resolver: refresh prepares the resolver before consuming the refresh
token, and later verification must not introduce a new network failure after
that token has rotated.

### Login

1. App `/auth/start` calls `provider.startLogin(returnTo, prompt)`.
2. Persist `transaction` in an encrypted HttpOnly cookie (web) or main-only memory
   or vault (desktop). Bind it to the initiating browser/device. Redirect to `url`.
   Never put the verifier/nonce/transaction into a UI response or localStorage.
3. App `/auth/exchange` passes its full callback URL and decrypted transaction to
   `provider.finishLogin(...)`. State, exact callback, issuer, expiry, single-use
   receipt, code/PKCE, ID token signature/claims/nonce/hashes and UserInfo subject
   are validated. Duplicate query parameters are rejected.
4. `sessions.create(verifiedLogin)` returns `{ handle, session }`. Keep the handle
   in the app's HttpOnly cookie or trusted desktop vault; expose only `session`.
5. Clear the transaction cookie using its original attributes. Navigate to the
   validated relative `returnTo`. Never create a new session from a refresh token
   alone after logout.

`createAuthCipher({ key, audience })` supplies A256GCM encryption for transaction
and credentials payloads. Supply a unique 32-byte key from the app's key manager;
key derivation/rotation is app-owned. Purposes and audiences are bound and expiry
is checked. `open` returns **unknown**: validate using `loginTransactionSchema`,
`oauthCredentialsSchema` and the app's complete stored-session schema.

### App session / refresh / local logout

`sessions.get(handle)` hashes the opaque handle, reads the authoritative store,
validates expiry/binding/revocation/local status, and refreshes if required.
`sessions.get(handle, { fresh: true })` forces online identity validation.
`sessions.credentials(handle, { fresh: true })` performs the same authoritative
locked operation but returns credentials for server/main-process use only. Never
serialize that result into an HTTP/IPC response or UI store. See
[shared modules](./modules.md) for HTTP/retry, discovery/session binding, BFF and
desktop RPC/shortcut extraction APIs.
Refresh rotation is committed **before** UserInfo; a transient UserInfo failure
does not lose the newly issued refresh token. Rejection ends the local session;
availability errors remain errors, not an authenticated or anonymous fallback.

`sessions.logout(handle)` deletes the local session **first** and attempts remote
token revocation. Its `remoteRevoked` result lets the app report/retry a provider
outage without restoring local login. Also clear the HttpOnly cookie/vault in
the app's boundary handler, even if the remote provider is unavailable.
`provider.logoutUrl()` builds the registered SSO end-session navigation without
putting tokens in URLs. SSO owns its confirmation and session cookies.

Protect custom cookie-authenticated mutation routes with exact origin/Fetch
Metadata checks using `assertMutationOrigin`, and the app's existing CSRF layer.
This helper does not replace rate limiting, CSRF tokens, trusted-proxy validation,
route authorization, or Better Auth's own checks. `authCookieOptions` provides
host-only HttpOnly/Lax attributes; use `secure: true` in production and the exact
same path/security attributes for deletion. Never share these cookies across apps.

## Required storage semantics

There is intentionally **no default in-memory production adapter**. App adapters
may use Drizzle/PostgreSQL, SQLite/vault, Redis or another durable store. The
contracts require real atomic operations, not read-then-write emulation.

| Adapter                   | Required guarantees                                                                                                                 |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `LoginStorage`            | Atomic unique hashed-state reservation and delete-if-unexpired consume across instances                                             |
| `SessionStorage.withLock` | Exclusive refresh across every process touching this store; renew distributed leases and fence expired owners before provider calls |
| `SessionStorage.insert`   | Unique insert, atomically reject a currently revoked subject/sid                                                                    |
| `SessionStorage.replace`  | Compare-and-set on revision, never upsert; atomically check revocation; commit before resolving                                     |
| `SessionStorage.remove`   | Atomic delete, optional revision match; cannot be undone by pending refresh                                                         |
| `LogoutStorage.apply`     | In one transaction: deduplicate jti, persist marker and invalidate matching sessions; rollback all three on failure                 |
| `LogoutStorage.isRevoked` | Evaluate unexpired markers for the verified identity/session; fail closed if storage is unavailable                                 |
| `ProofStorage.consume`    | Atomic insert-if-absent for a live replay key with expiry; never overwrite a live reservation                                       |

**Do not implement `withLock` as one uncommitted SQL transaction covering refresh
and UserInfo.** A rotation checkpoint must remain durable even if UserInfo later
fails. A session-scoped advisory lock or correctly fenced distributed lock can
protect the sequence while each checkpoint commits independently. SQLite/main-only
vault adapters may serialize operations in the sole owner process and use durable
atomic writes; multiple owners still need cross-process exclusion.

`replace` CAS protects logout and revision changes, but CAS alone does **not**
prevent two workers from presenting the same refresh token to SSO. That is why
`withLock` and fencing are mandatory. A plain `Map`/Promise single-flight is only
an appropriate test fixture or single-owner development implementation.
Timeouts during token rotation can be ambiguous: no client-side abstraction can
recover a consumed refresh token that SSO never returned. Fail closed if the next
attempt is rejected; never retry rotation in an unbounded loop.

### Mapping the ecosystem's five-table contract

The module does not own ORM schema or migrations. Existing app columns can carry
these adapters without adding a second authority:

- `user`: map stable `subject` to `externalUserId`; preserve app role/status.
- `session`: hash `handle` into `tokenHash`, map `sid`, user ID and expiry. Encrypt
  credentials and revision/freshness metadata together inside `credentials`.
  `StoredSession` is an adapter record, not a new table definition.
- `verification`: `stateHash` + `expiresAt` reserve/consume the login receipt.
- `revocation`: `jti`, `sid`, `subject`, `expiresAt` = `revokeUntil`; retain each
  receipt for at least its acceptance window. For subject-only cutoff matching,
  persist the validated logout `issuedAt` in the marker's `createdAt`. JWT iat is
  second-precision: include the end of that second when comparing app timestamps.
- `proof`: `key` + `expiresAt` store DPoP reservations.

If sid and subject both exist, match **both**, not an OR condition. Sid revokes
that entire SSO session; subject-only logout invalidates sessions established no
later than the logout issuance second, not future independent logins. A duplicate
jti must be an idempotent success/no-op and must not repeat session deletion.
Session insert/replace and marker application must share a transaction-safe
revocation fence; checking a marker and writing later is insufficient.

### Signed back-channel logout

`backchannel.verify(token)` validates only, without consuming anything.
`backchannel.handle(token)` verifies and invokes atomic `LogoutStorage.apply`.
Issuer, audience, typ `logout+jwt`, signature, iat/exp, jti, empty logout event,
sid/sub and absence of nonce are checked. Apps still own provider registration,
the HTTPS endpoint, request size/content-type limits, response codes and delivery
availability. Do not accept unsigned front-channel data as a back-channel receipt.

## Resource APIs and DPoP

`createResourceAuth` delegates token/request validation to Better Auth
`verifyAccessTokenRequest`, supplying the persistent DPoP replay adapter and
checking revocation before returning claims. It enforces exact issuer/audience,
scope, allowed asymmetric algorithms and token expiry. Requests include the actual
method/URL, Authorization scheme and proof; do not spoof these from untrusted
forwarding headers. A proof replay store alone is **not** proof verification.

By default user tokens must contain sid. Providers without sid require
`requireSid: false` **and** `onlineVerification: "always"`. With sid,
`onlineVerification: "sensitive"` supports local JWT + revocation for routine
requests and online verification for `verify(request, { sensitive: true })`.
`verifyActive(claims, request)` is an app-supplied UserInfo/introspection check;
DPoP-bound tokens require the appropriate verifier/introspection, not a replayed
proof from a different target. Remote introspection credentials remain server-only.
Apps still enforce local user status, roles, authorization and rate limits.

HTTP boundaries should map `rejected` to 401, `forbidden` (insufficient scope) to
403 and `unavailable` to 503; origin/CSRF rejection is a 403 at that specific
boundary. Emit the appropriate WWW-Authenticate challenge for protected resource
routes. Never return raw provider/storage exception details.

Official version-matched reference:
[Better Auth 1.7.7 OAuth Provider documentation](https://github.com/better-auth/better-auth/blob/v1.7.7/docs/content/docs/plugins/oauth-provider.mdx).

## UI store and desktop adapter

```ts
import { createAuthClient } from "@gorth/structure/modules/auth/client";

const auth = createAuthClient({
  read: readAppSession, // same-origin caller or trusted preload IPC
  login: startAppLogin, // app-owned navigation, never token exchange in UI
  logout: endAppSession, // app-owned protected mutation or trusted main IPC
});
// React: useSyncExternalStore(auth.subscribe, auth.getSnapshot, auth.getSnapshot)
// Load on client mount; do not share this mutable UI store across SSR requests.
```

States distinguish loading, authenticated, anonymous and unavailable/error.
An old session-read response cannot undo logout. Actions are coordinated per store;
view observers cannot disrupt auth. Dispose the store on its owning UI lifecycle.
App adapters must return deliberately projected users, not entire DB rows or token
payloads. The package cannot infer which fields in a generic app User are private.

On desktop, `createDesktopLogin({ provider, adapter })` receives the app's `listen`,
`open` and `close` functions. Listener registration precedes navigation, only the
registered fixed-port loopback callback/state is accepted, and cancellation/expiry
clean up the listener/window. The same provider does full OAuth verification.
App-owned transport/storage/close operations must themselves be bounded and honor
AbortSignal where applicable. Validate IPC sender/window/frame in the app. Keep
transactions, credentials, encryption keys and session handles out of renderer IPC.

## Verification and rollout

```sh
pnpm typecheck
pnpm test:types
pnpm test
pnpm build
pnpm test:exports
```

Tests cover PKCE/single-use callbacks, signed identity and token hashes, cookie/origin
policy, cipher binding, cross-instance refresh, transient UserInfo failures, logout
races, local status, stale UI responses, resource scopes/audience/DPoP/replay and
desktop callback/cancellation cleanup. Export tests exercise generated ESM/CJS and
inspect the browser entry graph. Fixtures are not production DB adapters.

No consuming app, SSO configuration, cloud DB or app deployment was changed by
this package implementation. Real database-adapter atomicity and live SSO/browser
end-to-end flows must be verified when apps are migrated after publication.
Existing package version, release visibility (`private: true`) and legacy exports
were preserved; adjust release metadata through the owner's publishing workflow.
