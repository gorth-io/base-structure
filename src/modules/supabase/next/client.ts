import type { DatabaseSchema, DefaultSchema } from "@/utils/interface";
import { createBrowserClient } from "@supabase/ssr";
import type { SupabaseClientOptions } from "@supabase/supabase-js";

export function createNextClient<
  Database = any,
  SchemaName extends DatabaseSchema<Database> = DefaultSchema<Database>,
>(
  url: string,
  publishableKey: string,
  options?: SupabaseClientOptions<SchemaName>,
) {
  return createBrowserClient<Database, SchemaName>(
    url,
    publishableKey,
    options,
  );
}
