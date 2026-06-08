import { stripe } from "@/lib/stripe";
import { supabaseAdmin } from "@/lib/supabase/admin";
import { removeDomain } from "@/lib/vercel-domains";

// 8.5 -> must be OK.
// On cancellation the handler flips the plan to free and tears the custom
// domain down: it removes it at the provider and disables the agency_domains row.
export async function handle(event: any) {
  if (event.type === "customer.subscription.deleted") {
    const customerId = event.data.object.customer as string;
    const { data: profile } = await supabaseAdmin
      .from("profiles")
      .update({ plan: "free" })
      .eq("stripe_customer_id", customerId)
      .select("id")
      .single();

    await removeDomain(customerId);
    await supabaseAdmin
      .from("agency_domains")
      .update({ status: "disabled" })
      .eq("profile_id", profile?.id);
  }
}
