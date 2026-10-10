import type {
  CommonCookieMethods,
  DatabaseSchema,
  DefaultSchema,
} from "@/utils/interface";
import { createServerClient } from "@supabase/ssr";
import type { SupabaseClientOptions } from "@supabase/supabase-js";

export function createServer<
  Database = any,
  SchemaName extends DatabaseSchema<Database> = DefaultSchema<Database>,
>(
  url: string,
  publishableKey: string,
  cookies: CommonCookieMethods,
  options?: SupabaseClientOptions<SchemaName>,
) {
  return createServerClient<Database, SchemaName>(url, publishableKey, {
    ...options,
    cookies: {
      getAll() {
        return cookies.getAll();
      },
      async setAll(cookiesToSet, headers) {
        try {
          await cookies.setAll?.(cookiesToSet, headers);
        } catch {
          /* A read-only server render cannot persist refreshed cookies. */
        }
      },
    },
  });
}
export type { CommonCookieMethods } from "@/utils/interface";
