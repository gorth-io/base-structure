# Shared modules

See [auth.md](auth.md) for SDK boundaries and breaking legacy removals.

| Module                     | Responsibility                                                                                                                                |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `modules/auth/client`      | Framework-independent request retry coordination and freshness decisions                                                                      |
| `modules/auth/server`      | Identity cache/validator, native-session grant guard, revocation predicate, origin checks, native SDK resource verification and signed logout |
| `modules/http`             | Injected Axios fetcher/caller, validation, safe errors, Web Response conversion                                                               |
| `modules/desktop`          | Framework-free RPC packets and shortcut validation; not an auth engine                                                                        |
| `modules/common`           | Supabase admin/client/realtime/upload helpers                                                                                                 |
| `modules/supabase/next`    | Supabase SSR integration                                                                                                                      |
| `modules/supabase/express` | Supabase server/client integration                                                                                                            |

All configuration, credentials, adapters, callbacks, runtime platform objects
and service destinations are supplied by the owning app. No module reads env,
connects to DB on import, creates a configured Better Auth instance, opens a
listener, or imports UI. Reusable contracts live in `src/utils/interface.ts`;
pure formatting lives in `src/utils/formatter.ts`. Internal module imports use
`@/` and async logic uses async/await with try/catch/finally.

HTTP callers retain injected runtime adapters (including desktop XHR) and do
not change QUIC/network settings. Caller mutations must opt into unsafe retries;
auth endpoints do not retry implicitly. Web Response conversion preserves
individual Set-Cookie, status and Location headers, and removes stale wire
encoding/length/hop-by-hop headers. Custom error mapping/notifications are app
callbacks, not UI package dependencies.

Desktop RPC still requires app-owned IPC sender/frame validation and trusted
preload transport. Shortcut policies/registration/persistence stay in the app.
Supabase credentials/RLS/ownership remain app responsibilities.

Use `pnpm verify` before releasing. Public SDK paths and optional host-framework
requirements are listed in auth.md. GitHub distribution remains private-to-npm;
pin consumers to a tested release commit/tag. No app dependency or DB/cloud state
is changed by building this package.
