import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
import { NextResponse } from "next/server";

// Single-tenant fixture: a personal note create endpoint. Cookie session auth,
// owner scoped by user_id. Nothing here resolves a customer from the Host.
export async function POST(req: Request) {
  const cookieStore = cookies();
  const supabase = createServerClient(SUPABASE_URL, SUPABASE_KEY, { cookies: cookieStore });
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "unauth" }, { status: 401 });

  const body = await req.json();
  await supabase.from("notes").insert({ user_id: user.id, body: body.text });
  return NextResponse.json({ ok: true });
}
