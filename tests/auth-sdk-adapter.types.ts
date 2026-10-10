import { createAuthClient as createBetterAuthClient } from "better-auth/client";
import {
  createSessionAuthAdapter,
  createAuthClient,
} from "../src/modules/auth/client";

// Compile against the installed SDK without making requests or configuring app auth.
const sdk = createBetterAuthClient({ baseURL: "https://auth.example.test" });
const adapter = createSessionAuthAdapter({
  getSession: (signal) => sdk.getSession({ fetchOptions: { signal } }),
  signOut: (signal) => sdk.signOut({ fetchOptions: { signal } }),
  mapUser: (user) => ({ id: user.id, name: user.name, email: user.email }),
  login: async () => {},
});
const state = createAuthClient(adapter);
const user = state.getSnapshot().session?.user;
const id: string | undefined = user?.id;
void id;
// Provider session secrets are not part of the projected user contract.
// @ts-expect-error public user projection does not expose a session token
user?.token;
