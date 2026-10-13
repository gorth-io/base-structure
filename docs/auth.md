# Native Better Auth integration

Targets the installed Better Auth 1.7.7 SDK. Applications own `betterAuth({...})`,
provider configuration, keys, trusted origins, database schemas/adapters,
business permissions, cookies and routing. This package never reads env or
connects to a database.

SSO uses the official OAuth Provider; relying-party web apps use Generic OAuth
with native account/session/verification storage. Electron uses the official
Electron SDK with its app backend. Do not create another OAuth/session engine
inside Structure or use an ID token as a service access token.

## App-owned SDK and required peer

`better-auth` is a **required peer dependency** (`^1.7.7`), not a runtime
dependency installed and re-exported by Structure. The package pins 1.7.7 in its
development dependencies only for builds and integration tests.

Every consuming application must declare its own direct `better-auth`
dependency, including Electron main and both runtimes of a split client/server
application. A package manager may auto-install peers, so the peer declaration
does not by itself enforce a direct dependency in the application's manifest.

```sh
pnpm add better-auth@1.7.7
```

Import native APIs directly:

```ts
import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/react";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import { requestToResourceInput, verifyAccessTokenRequest } from "better-auth/oauth2";
```

The `cores/auth` and `cores/auth/*` namespaces are retired and explicitly
blocked by the export map. There are no compatibility re-exports. Native
adapters, cookies, integrations and plugins must use their official package
paths (for example `better-auth/adapters/drizzle`, `better-auth/cookies` and
`better-auth/next-js`).

Install optional features only in the app that uses them: OAuth Provider,
enterprise SSO, Infra, SCIM, Stripe or Electron use their owning
`@better-auth/*` package directly. Structure no longer depends on any of
those feature packages. This is a breaking export change; publish a new
breaking release/tag and update consumers deliberately.

SDK clients use `signIn.social({ provider: configuredProviderId })` in 1.7.7;
Generic OAuth does not need an invented `genericOAuthClient` plugin.
`nextCookies` is server integration, not a renderer/client export.

## Modules retained because current apps use them

- `modules/auth/client`: `createAuthRetry`, `waitForAuthOperation`,
  `AuthError`, configurable freshness/policy helpers. SDK owns session renewal;
  retry only coalesces app-provided refresh/read callbacks, retries once after
  401, and fences late refresh results after reset/dispose.
- `modules/auth/server`: origin/return-path checks, SHA-256 fingerprints,
  `createResourceAuth`, `createProofReplayStore`, `createLogoutVerifier`
  and policy. API verification delegates to official
  `verifyAccessTokenRequest`; persistent proof/revocation and local permissions
  remain app-owned adapters.
- Signed back-channel logout is still used by the apps. Signature, issuer,
  audience, typ, expiry, event and replay checks cannot be removed just because
  app sessions are now native.

## New reusable helpers

### Identity cache

`createIdentityCache<Value>({ load, key?, maxAgeMs?, capacity?, maxPending?, now? })`
extracts the repeated UserInfo coalescing/cache logic. Default TTL is 120 seconds,
with 512 entries/pending operations; applications may override both.

```ts
import { createIdentityCache } from "@gorth/structure/modules/auth/server";

const profiles = createIdentityCache({
  load: loadValidatedActiveProfile,
  maxAgeMs: applicationIdentityMaxAgeMs,
});
const profile = await profiles.get(accessToken, { fresh: sensitive, signal });
await profiles.forget(accessToken); // invalidate when revoking this grant
profiles.clear(); // invalidate this factory on teardown/global invalidation
```

The loader owns endpoint allowlisting, timeout, schema/status validation and
safe rejection classification. Return immutable identity data. The default key
is a SHA-256 fingerprint; raw credentials are not Map keys. Do not pass a raw
token-returning custom `key` callback. A transient failure never returns expired
identity data. Fresh calls bypass the cache and coalesce a currently running
check. TTL starts before networking; already-stale results are not cached.
Cancellation aborts only the waiter, not other callers' shared check.
Invalidation fences older responses, including pending key derivation on clear.

This is an **identity-only process-local cache**, not an authorization or
distributed session/refresh/replay store. Every protected operation still checks
token expiry/audience/scopes, durable revocation and local permissions. Sensitive
operations can force an online check. Cache contents contain no tokens.

### Native identity validator

`createOAuthIdentityValidator({ providerId, subject, allowed? })` supplies
`user.validateUserInfo`. The caller selects its additional user subject field;
the helper accepts only that provider's SDK OAuth lifecycle with a matching
non-empty `profile.sub`. Optional `allowed(profile)` implements app-owned
identity status policy. Errors are safe identifiers, not provider payloads.

It does not verify/decode JWTs or create users. SDK verification must be enabled
in app provider configuration. Mutable email/username/SSO roles are never used
to link identities or elevate local roles. Profile mapping, defaults and schema
remain app-owned.

### Session grant guard

`createSessionGrantGuard({ read, assertAllowed, now? }).run(operation, signal?)`
surrounds a native SDK credential-access operation, for example
`auth.api.getAccessToken`. `read` returns an authoritative existing native
session binding (`id, userId, subject, sid?, expiresAt`); `assertAllowed` checks
durable revocation and local permissions.

The guard checks before/after the operation and rejects missing, expired,
revoked, cancelled or changed session/account bindings. It adds no session
storage, token refresh, encryption or cookie format. Use it **before** sending
the next upstream proxy request. It cannot undo a side effect or a request
already dispatched, and does not revoke provider tokens itself. Multi-instance
race prevention still needs the app's durable session/revocation fences.
SDK handles token rotation; app handles grant revocation on local sign-out.

### Revocation matching

`matchesAuthRevocation(marker, identity, now?)` is a pure predicate for
already-validated receipts. Both `sid` and subject must match when supplied;
a subject-only event covers sessions issued through the end of that JWT issuance
second, not future independent logins. All timestamps are epoch milliseconds.
Expired markers do not match. Signature verification, durable receipt uniqueness,
atomic session invalidation and retention remain with existing verifier/adapters.

## Breaking legacy removal

Removed runtime modules: custom OAuth/PKCE engine, custom session store/refresh
engine, discovery/JWKS snapshot cache, session-bound transport, BFF HMAC,
endpoint/schema helpers used only by those engines, purpose-bound JWE cipher,
custom UI auth store/session adapter and loopback desktop login orchestration.
Their dependent types, formatters, exports and package-only obsolete tests are
removed too. Do not create fallback shims.

Use native Generic OAuth, getSession/useSession/signOut/getAccessToken and
`@better-auth/electron` instead. Do not migrate old ciphertext into native
storage without an app-owned explicit migration.

Active runtime imports in the ten apps and SSO were inspected and retained.
Some **legacy consumer tests**, however, still exercise removed APIs:

- Chat `tests/auth.test.ts`: custom OAuth/session contracts.
- Browser and Launcher `tests/vitest/auth-timeout.test.ts`: `createDesktopLogin`.

These must be replaced with native SDK tests before their next package update;
they cannot continue to import intentionally deleted APIs. Archived `pkg`
sources/docs can also mention them. No app, installed package, DB or SSO
registration was modified in this package-only change.

Publish as a **major release** because exports were intentionally removed.
Version/tag/publication remains owner-controlled; current package version was
not silently bumped. Publish and refresh consumer lockfiles before adopting new
helpers. Other infrastructure modules (HTTP, desktop RPC/shortcuts, Supabase)
are preserved rather than assuming auth migration makes them obsolete.

## Verification

`pnpm verify` checks types, runtime tests, ESM/CJS build and public exports.
Tests cover SDK-native social login/account-selection/PKCE using an isolated
memory adapter, identity cache races, freshness, logout, grants, audience/scopes,
DPoP, browser-safe helper graphs, HTTP and desktop infrastructure.
Fixtures are not production adapters or a live browser/cloud end-to-end test.

References:

- [Generic OAuth](https://better-auth.com/docs/plugins/generic-oauth)
- [Session management](https://better-auth.com/docs/concepts/session-management)
- [OAuth Provider](https://better-auth.com/docs/plugins/oauth-provider)
- [Electron integration](https://better-auth.com/docs/integrations/electron)
