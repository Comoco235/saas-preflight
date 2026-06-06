"use server";

import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

// CASE (c) -> must NOT be flagged.
// A mutating Server Action. Next applies same-origin protection to Server
// Actions automatically, and it exports no HTTP method, so it is not a
// CSRF-prone route handler.
export async function deleteNote(id: string) {
  const supabase = createServerClient(SUPABASE_URL, SUPABASE_KEY, { cookies: cookies() });
  await supabase.from("notes").delete().eq("id", id);
}
