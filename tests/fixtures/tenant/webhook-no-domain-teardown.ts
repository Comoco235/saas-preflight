import { stripe } from "@/lib/stripe";
import { supabaseAdmin } from "@/lib/supabase/admin";

// 8.5 -> MUST be MISSING.
// On cancellation the handler only flips the plan to free. It never tears
// anything down, so the paid white-label feature keeps working for free.
export async function handle(event: any) {
  if (event.type === "customer.subscription.deleted") {
    const customerId = event.data.object.customer as string;
    await supabaseAdmin
      .from("profiles")
      .update({ plan: "free" })
      .eq("stripe_customer_id", customerId);
  }
}
