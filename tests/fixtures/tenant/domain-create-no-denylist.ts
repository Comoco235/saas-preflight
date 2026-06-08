import { supabaseAdmin } from "@/lib/supabase/admin";

// 8.3 -> MUST be flagged.
// A tenant picks its own subdomain and we store it with no check against
// privileged names, so a tenant can claim admin, api, www, or the brand name.
export async function createSubdomain(profileId: string, subdomain: string) {
  await supabaseAdmin
    .from("agency_domains")
    .insert({ profile_id: profileId, subdomain, status: "pending" });
}
