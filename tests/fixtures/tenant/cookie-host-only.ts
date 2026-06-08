import { cookies } from "next/headers";

// 8.1 -> must NOT be flagged.
// The auth cookie is host-only (no domain attribute), so a tenant subdomain
// cannot read another tenant's session. This is the safe default.
export function setSession(token: string) {
  cookies().set("sb-access-token", token, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
  });
}
