# Tenant isolation (Lens 8, multi-tenant and white-label)

This lens only applies to multi-tenant apps, the kind where one customer (a
tenant, org, agency, or workspace) has its own users, its own data, and often
its own subdomain or custom domain. White-label SaaS on the Next.js + Supabase +
Stripe stack is the typical shape: every tenant gets `tenant.yourapp.com` or a
custom domain, with branding and isolated data.

The other seven lenses reason about user versus user. This one reasons about
tenant versus tenant, which is a different and often unguarded boundary. A
correct per-user check (a user can only see their own rows) can still leak across
tenants if the scoping key is the user and not the org, or if a session cookie is
shared across every tenant subdomain.

Run this lens only when the app is actually multi-tenant. Signals: a tenant, org,
agency, or workspace table; subdomain or Host-based routing in middleware; a
table of customer domains; code that resolves a tenant from the request Host. If
none of these are present, the app is single-tenant and this lens does not apply,
say so in one line and move on.

Contents:
1. Session cookie scope (cross-tenant session theft)
2. Tenant context resolution (Host and header spoofing)
3. Tenant scoping versus user scoping (cross-tenant IDOR)
4. Subdomain and domain creation validation
5. Domain lifecycle on downgrade and cancellation
6. White-label content (SSRF and injection through tenant-controlled input)

## 1. Session cookie scope

The highest-value check in this lens, and the one generic scanners never make.
If the auth or session cookie is set with an explicit `domain` attribute scoped
to a parent domain (for example `.yourapp.com`), the browser sends that cookie to
every subdomain. On a per-tenant subdomain model, that means tenant A's browser
sends its session cookie to `tenant-b.yourapp.com`, so a malicious or
compromised tenant subdomain can read another tenant's session. That is
cross-tenant account takeover.

How to verify:
* Find where auth and session cookies are set. With `@supabase/ssr`, this is the
  `cookies` handlers passed to `createServerClient`, plus any direct
  `cookies().set(...)` or response `cookies.set(...)`.
* Confirm no `domain` attribute is set on the auth cookie, or that it is set to
  the exact host only, never a leading-dot parent domain. No `domain` attribute
  means host-only, which is the safe default and what you want.
* If a parent `domain` is set, confirm it is genuinely required (rare) and that
  auth is confined to a single non-tenant host. If not, this is a finding.

Worked example:
Vulnerable: the session cookie is set with `domain: '.yourapp.com'`, so it is
shared by every `*.yourapp.com` tenant.
Fixed: no `domain` attribute on the auth cookie, so it is host-only and a tenant
subdomain cannot read another tenant's session.

## 2. Tenant context resolution

The app decides which tenant a request belongs to, usually from the request Host
or a custom header. Two failure modes:

Header injection. If middleware reads a tenant-identifying header (for example
`x-app-tenant`) from the incoming request and trusts it, an attacker sets that
header directly and switches tenants. Internal tenant headers must be stripped
from the incoming request unconditionally before any routing logic, then set by
the server from the trusted Host. Verify there is an unconditional delete of the
inbound tenant header at the top of the middleware, before any branch.

Host trust. The tenant is derived from the Host. Confirm the Host is the
platform-validated value, not an attacker-supplied header that the framework
does not validate. Behind a proxy, use the proxy's trusted forwarded host.

Worked example:
Vulnerable: middleware reads `request.headers.get('x-app-tenant')` and routes on
it without removing any inbound value.
Fixed: middleware first calls `requestHeaders.delete('x-app-tenant')`
unconditionally, resolves the tenant from the validated Host, then sets the
header itself for downstream use.

## 3. Tenant scoping versus user scoping

A query or RLS policy that scopes by `user_id` alone is correct for personal data
but wrong for tenant-shared data. If a resource belongs to an org and the policy
only checks the current user, a user who moves between orgs, or a crafted
request, can reach another tenant's rows. The scoping key for tenant-owned data
must be the tenant identifier (org_id, tenant_id, profile_id for an agency), not
just the user.

How to verify, for every tenant-owned table:
* The RLS policy and the application query both scope by the tenant key, verified
  in the database, not only in code.
* A request authenticated inside tenant A cannot read or write a row whose tenant
  key is tenant B, even by passing that row's id. This is the tenant-level
  version of IDOR from Lens 1.
* Membership and role changes are enforced server-side. Belonging to a tenant is
  not the same as being allowed to act on every resource in it.

This control is mostly confirmed by reading the policies and the queries. The
scanner can surface tenant tables and queries that filter by user only, but the
verdict comes from reading.

## 4. Subdomain and domain creation validation

When tenants choose their own subdomain or add a custom domain, unvalidated input
lets a tenant claim a reserved name or break routing.

How to verify:
* There is a strict format allow-list for the subdomain or slug (length,
  character set), enforced server-side, not only in the form.
* There is a deny-list of reserved names: at minimum `www`, `app`, `api`,
  `admin`, `mail`, `static`, `assets`, and the brand's own name. A tenant must
  not be able to register `admin.yourapp.com`.
* Custom domains are verified for ownership before they are served, and the
  apex and wildcard of your own domain cannot be claimed by a tenant.

## 5. Domain lifecycle on downgrade and cancellation

Provisioning a tenant domain is the path everyone codes. Tearing it down is the
path that rots. If a tenant downgrades off the paid plan or cancels, and the
custom domain or subdomain is not deprovisioned, the paid feature keeps working
for free, and you can be left with an orphaned domain on your hosting provider.

How to verify the cancellation and downgrade paths:
* On `customer.subscription.deleted` and on any downgrade out of the plan that
  granted the domain, the domain record is disabled or removed, the domain is
  removed from the hosting provider, and any tenant resolution cache is
  invalidated.
* The action that removes or disables a domain is not itself gated behind the
  paid feature that was just lost. A downgraded tenant must still be able to
  clean up. Gating teardown behind the lost capability strands the domain.

Worked example:
Vulnerable: the webhook sets `plan = 'free'` on cancellation but never touches the
domains table, so the custom domain keeps resolving and serving the portal.
Fixed: the cancellation path sets the domain record to disabled, calls the
provider's remove-domain API, and invalidates the tenant cache.

## 6. White-label content

Tenant-controlled branding is attacker-controlled input wearing a friendly name.
This control mostly cross-references Lens 5 (input validation, SSRF, injection),
applied to the tenant surface:

* Custom domain verification must not fetch an attacker-supplied URL or host in a
  way that enables SSRF. The verification target must be a fixed provider API,
  with the tenant value passed as encoded data, never as the request destination.
* Brand color, theme, and any styling value a tenant supplies must be validated
  to a strict format (for a color, a strict hex pattern) and re-validated at
  render time, so a poisoned value cannot inject CSS or break out of an attribute.
* Tenant-supplied logos, HTML, or rich content follow the same XSS rules as any
  user content. No raw HTML or CSS from a tenant reaches the page unsanitized.
