import { createCommonPublicClient } from "@/modules/common/admin";
import type { SupabaseClientOptions } from "@supabase/supabase-js";

export function createExpressClient(
  url: string,
  anonOrPublishableKey: string,
  options?: SupabaseClientOptions<"public">,
) {
  return createCommonPublicClient(url, anonOrPublishableKey, options);
}
