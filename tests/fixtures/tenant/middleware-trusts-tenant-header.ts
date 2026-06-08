import { NextResponse, type NextRequest } from "next/server";

// 8.2 -> MUST be MISSING.
// The middleware reads the tenant from an inbound header without stripping it
// first, so an attacker forges x-app-tenant and switches tenants.
export function middleware(request: NextRequest) {
  const tenant = request.headers.get("x-app-tenant");
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-app-tenant", tenant ?? "public");
  return NextResponse.next({ request: { headers: requestHeaders } });
}
