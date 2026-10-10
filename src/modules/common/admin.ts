import type { SupabaseClientOptions } from "@supabase/supabase-js";
import { createClient } from "@supabase/supabase-js";

export function createCommonAdminClient(
  url: string,
  serviceRoleKey: string,
  options?: SupabaseClientOptions<"public">,
) {
  return createClient(url, serviceRoleKey, options);
}

export function createCommonPublicClient(
  url: string,
  anonOrPublishableKey: string,
  options?: SupabaseClientOptions<"public">,
) {
  return createClient(url, anonOrPublishableKey, options);
}
