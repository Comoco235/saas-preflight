import { createClient } from "@supabase/supabase-js";
import { NextResponse } from "next/server";

// CASE (b) -> must NOT be flagged.
// Authenticated by an Authorization: Bearer token, not a cookie. The browser
// does not attach this header cross-site, so this is not CSRF-prone, even though
// it calls getUser().
export async function POST(req: Request) {
  const token = req.headers.get("authorization")?.replace("Bearer ", "");
  const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
  const { data: { user } } = await supabase.auth.getUser(token);
  if (!user) return NextResponse.json({ error: "unauth" }, { status: 401 });

  const body = await req.json();
  return NextResponse.json({ received: body });
}
