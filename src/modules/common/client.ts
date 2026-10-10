import type { CommonCookieMethods } from "@/utils/interface";
import { createBrowserClient, createServerClient } from "@supabase/ssr";
import type { SupabaseClientOptions } from "@supabase/supabase-js";

export function createCommonBrowserClient<
  Database = any,
  SchemaName extends string & keyof Omit<Database, "__InternalSupabase"> =
    "public" extends keyof Omit<Database, "__InternalSupabase">
      ? "public"
      : string & keyof Omit<Database, "__InternalSupabase">,
>(
  url: string,
  publishableKey: string,
  options?: SupabaseClientOptions<SchemaName>,
) {
  return createBrowserClient<Database, SchemaName>(url, publishableKey, {
    ...(options ?? {}),
  });
}

export function createCommonServerClient<
  Database = any,
  SchemaName extends string & keyof Omit<Database, "__InternalSupabase"> =
    "public" extends keyof Omit<Database, "__InternalSupabase">
      ? "public"
      : string & keyof Omit<Database, "__InternalSupabase">,
>(
  url: string,
  publishableKey: string,
  cookies: CommonCookieMethods,
  options?: SupabaseClientOptions<SchemaName>,
) {
  return createServerClient<Database, SchemaName>(url, publishableKey, {
    ...options,
    cookies,
  });
}

export type { CommonCookieMethods } from "@/utils/interface";
