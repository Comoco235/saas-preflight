import { NextResponse, type NextRequest } from "next/server";

// 8.2 -> must be OK.
// The middleware unconditionally deletes any inbound tenant header before any
// branch, then sets it from the trusted Host. The legitimate re-read after the
// strip must not flip this back to MISSING.
export function middleware(request: NextRequest) {
  const requestHeaders = new Headers(request.headers);
  requestHeaders.delete("x-app-tenant");

  const host = request.headers.get("host") ?? "";
  const tenant = host.split(".")[0];
  requestHeaders.set("x-app-tenant", tenant);
  return NextResponse.next({ request: { headers: requestHeaders } });
}
