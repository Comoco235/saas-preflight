import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
import { NextResponse } from "next/server";

// CASE (a) -> MUST be flagged EXPOSED.
// Cookie-session auth, mutating method, and NO Origin/Referer check or CSRF token.
export async function POST(req: Request) {
  const cookieStore = cookies();
  const supabase = createServerClient(SUPABASE_URL, SUPABASE_KEY, { cookies: cookieStore });
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "unauth" }, { status: 401 });

  const body = await req.json();
  await supabase.from("notes").insert({ user_id: user.id, text: body.text });
  return NextResponse.json({ ok: true });
}
