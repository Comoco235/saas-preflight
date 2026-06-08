import { supabaseAdmin } from "@/lib/supabase/admin";

// 8.3 -> must NOT be flagged.
// The subdomain is checked against a reserved-name deny-list before insert, so
// a tenant cannot claim a privileged name.
const RESERVED = ["www", "app", "api", "admin", "mail", "static", "assets"];

function isReserved(name: string): boolean {
  return RESERVED.includes(name.toLowerCase());
}

export async function createSubdomain(profileId: string, subdomain: string) {
  if (isReserved(subdomain)) {
    throw new Error("This subdomain is reserved.");
  }
  await supabaseAdmin
    .from("agency_domains")
    .insert({ profile_id: profileId, subdomain, status: "pending" });
}
