# Auth and isolation (Lens 1)

The single most common P0 in a vibe-coded SaaS: a user can read or write data
that is not theirs, because the only thing standing between them and the row was
a check that lives in the frontend, or a Supabase table with row level security
turned off, or a middleware that fails open.

Contents:
1. Server-side auth on every protected route and action
2. Middleware fail-open
3. Supabase row level security (RLS)
4. Object ownership (IDOR)

## 1. Server-side auth on every protected route and action

The rule: the client cannot be trusted to enforce access. A hidden button, a
redirect on the dashboard page, a disabled form: none of these stop a user from
calling the API directly with curl. Authorization must happen on the server, in
the route handler or server action itself, on every request.

What to verify, per route handler and server action:
* It resolves the current user from the session on the server, for Supabase
  typically `const { data: { user } } = await supabase.auth.getUser()`.
* It returns 401 when there is no user, before doing any work.
* It checks that the user is allowed to touch the specific resource, not just
  that they are logged in. Logged in is not the same as authorized.

Failure pattern: a route reads `params.id`, queries the row, and returns it,
with an auth check that only confirms a session exists. Any logged-in user can
pass any id and read someone else's row. That is an IDOR, see section 4.

Note on `getSession` vs `getUser`: in server code that makes a trust decision,
prefer `getUser`, which revalidates the token with Supabase. `getSession` reads
the cookie and can be stale or spoofed in some setups. Flag trust decisions made
on `getSession` alone.

## 2. Middleware fail-open

Next.js `middleware.ts` is often where auth gating is centralized. Two classic
P0s:

Fail-open on error. If the middleware wraps its auth logic in try/catch and the
catch returns `NextResponse.next()`, then any error in the auth check (Supabase
timeout, thrown exception) lets the request through. Under load or during a
provider hiccup, the door opens for everyone. The fix: on error, fail closed,
redirect to login or return 401.

Matcher gaps. The `config.matcher` defines which paths the middleware runs on.
If a protected route is not covered by the matcher, the middleware never runs
there and the route is unguarded. Verify the matcher actually covers every
protected path, and remember middleware is a convenience layer: the route itself
must still check auth (defense in depth), because matchers drift.

## 3. Supabase row level security (RLS)

RLS is the real boundary for Supabase data. If RLS is off on a table, the anon
or authenticated key can read and write every row, no matter how clean the app
code looks. You cannot confirm RLS from the app code alone. You must check the
database.

How to verify:
* Look for migration files or `supabase/` SQL that runs
  `alter table X enable row level security` for every table holding user data.
* Confirm each such table has policies that scope rows to the owner, typically
  `auth.uid() = user_id`, separately for select, insert, update, delete.
* A table with RLS enabled but no policy denies all access by default for the
  anon and authenticated roles, which is safe but will look like a bug to the
  app. A table with RLS disabled is the danger.

Service role bypasses RLS entirely. Any code path that uses the service role key
is operating with full database access and must enforce ownership in code
itself. Service role must never be reachable from the browser bundle (it is a
server-only secret). If you find the service role key used inside a route that
serves user requests, treat every query in that route as unguarded until proven
otherwise.

## 4. Object ownership (IDOR)

Insecure Direct Object Reference: the app accepts an identifier from the user
and acts on the matching record without checking the user owns it. Sequential or
guessable ids make it trivial; UUIDs make it harder but not safe, ids leak.

How to verify, for every route that takes an id, slug, or key from the request:
* The query filters by the owner as well as the id, or RLS enforces ownership,
  or the code explicitly compares the record's owner to the current user before
  proceeding.
* This applies to writes and deletes too, not just reads. A delete-by-id with no
  ownership check lets a user delete other users' data.

Worked example:
Vulnerable shape: take `id` from the request, `select * from invoices where id =
:id`, return it. Any user reads any invoice.
Fixed shape: `select * from invoices where id = :id and user_id = :currentUser`,
or rely on an RLS policy `auth.uid() = user_id`, and return 404 (not 403) when
nothing matches, so you do not confirm the row exists to someone who should not
see it.
