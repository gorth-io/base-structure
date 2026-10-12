# @gorth/structure

Shared, configurable runtime infrastructure for the Gorth ecosystem.
Better Auth owns login, OAuth, sessions, token encryption and renewal; Structure
provides direct SDK exports and small reusable infrastructure helpers.

See [auth](docs/auth.md) for the native SDK boundaries, new helpers and
**breaking removal of the legacy custom auth engines**, and
[modules](docs/modules.md) for the public module inventory and verification.

No application configuration, env reads, API keys, database connection or
configured auth instance belongs in this package.
