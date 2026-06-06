import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
import { NextResponse } from "next/server";

// CASE (d) -> must NOT be flagged.
// Cookie-session auth and mutating, but it verifies the Origin header, so it is
// protected against CSRF.
export async function POST(req: Request) {
  const origin = req.headers.get("origin");
  if (origin !== process.env.APP_URL) {
    return NextResponse.json({ error: "bad origin" }, { status: 403 });
  }

  const supabase = createServerClient(SUPABASE_URL, SUPABASE_KEY, { cookies: cookies() });
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "unauth" }, { status: 401 });

  const body = await req.json();
  await supabase.from("comments").insert({ user_id: user.id, text: body.text });
  return NextResponse.json({ ok: true });
}
