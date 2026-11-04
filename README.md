# @gorth-io/structure

TypeScript infrastructure for HTTP clients, authentication coordination,
Supabase, and database integrations in the **gorth-io** ecosystem.

| Includes | Public imports |
| --- | --- |
| HTTP callers, fetchers, and responses | `@gorth-io/structure/modules/http` |
| Authentication retry and freshness policies | `@gorth-io/structure/modules/auth/client` |
| Server authentication infrastructure | `@gorth-io/structure/modules/auth/server` |
| Desktop infrastructure | `@gorth-io/structure/modules/desktop` |
| Axios, Zod, Supabase, and database SDKs | `@gorth-io/structure/cores/*` |

## Installation

Use Node.js 24 and install from the npm registry with Bun:

```bash
bun add @gorth-io/structure
```

Example dependency declaration (`0.0.0` is a demo version; replace it with an available release):

```json
{
  "dependencies": {
    "@gorth-io/structure": "0.0.0"
  }
}
```

## Usage

Import the public entrypoint for the integration you need:

```ts
import axios from "@gorth-io/structure/cores/axios";
import { z } from "@gorth-io/structure/cores/zod";

const User = z.object({
  id: z.string(),
  name: z.string(),
});

export async function getUser() {
  const response = await axios.get("/user", { withCredentials: true });
  return User.parse(response.data);
}
```

Each application supplies its own URLs, credentials, database connections, and
authentication configuration. Import only the entrypoints suitable for your
runtime; keep server credentials and database operations outside browser code.

## Authentication

Better Auth owns login, OAuth, sessions, token encryption, and renewal. Structure
provides SDK exports and small reusable infrastructure helpers, including
request retry coordination and freshness policies. It does not replace the
authentication provider or create a configured auth instance for your app.

See the [authentication guide](https://github.com/gorth-io/base-structure/blob/main/docs/auth.md)
and [public module inventory](https://github.com/gorth-io/base-structure/blob/main/docs/modules.md)
for integration details and migration notes.

No application configuration, env reads, API keys, database connection or
configured auth instance belongs in this package.

## Development

```bash
bun install --frozen-lockfile
bun run build
bun run typecheck
bun run test
bun run test:types
bun run test:exports
```

## Related packages

- [@gorth-io/primitive](https://www.npmjs.com/package/@gorth-io/primitive): React UI, themes, and application components.
- [@gorth-io/principle](https://www.npmjs.com/package/@gorth-io/principle): backend middleware and server integrations.
