import { cookies } from "next/headers";

// 8.1 -> MUST be flagged.
// The auth/session cookie is set with a parent domain, so every *.app.com tenant
// subdomain receives it. A malicious tenant subdomain can read another tenant's
// session: cross-tenant account takeover.
export function setSession(token: string) {
  cookies().set("sb-access-token", token, {
    httpOnly: true,
    sameSite: "lax",
    domain: ".app.com",
  });
}
