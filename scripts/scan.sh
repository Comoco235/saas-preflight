#!/usr/bin/env bash
#
# saas-preflight scanner
#
# Prints candidate findings for a Next.js + Supabase + Stripe SaaS, grouped by
# the 7 audit lenses. Every line is a LEAD, not a verdict. Grep cannot prove a
# vulnerability: it misses real issues and flags safe code. Use the output to
# decide what to read, then confirm by reading the actual code.
#
# Usage: bash scan.sh <path-to-repo>
# Read-only. Makes no changes.

set -u

ROOT="${1:-.}"
if [ ! -d "$ROOT" ]; then
  echo "saas-preflight: '$ROOT' is not a directory." >&2
  echo "Usage: bash scan.sh <path-to-repo>" >&2
  exit 1
fi

# Prefer ripgrep, fall back to grep -r. Both skip node_modules and build dirs.
if command -v rg >/dev/null 2>&1; then
  SEARCH() { rg -n --no-heading -S -g '!node_modules' -g '!.next' -g '!dist' -g '!build' -g '!.git' -g '!*.lock' -g '!*.md' -g '!*.mdx' -g '!*.txt' "$@" "$ROOT" 2>/dev/null; }
else
  SEARCH() {
    # last arg is the pattern when called as SEARCH "pattern"; emulate rg -n -S
    grep -rniE --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=dist --exclude-dir=build --exclude-dir=.git --exclude=*.md --exclude=*.mdx --exclude=*.txt "$1" "$ROOT" 2>/dev/null
  }
fi

hits() { # hits "<pattern>" -> prints matches or nothing
  SEARCH "$1"
}

section() { printf '\n========== %s ==========\n' "$1"; }
check()   { printf '\n[%s]\n  why: %s\n' "$1" "$2"; }
none()    { printf '  (no candidates)\n'; }

run() { # run "<label>" "<why>" "<pattern>"
  check "$1" "$2"
  local out
  out="$(hits "$3")"
  if [ -n "$out" ]; then printf '%s\n' "$out" | sed 's/^/  /'; else none; fi
}

echo "saas-preflight scan of: $ROOT"
echo "Every match below is a lead to verify by reading the code. Not a verdict."

# ---------------------------------------------------------------------------
section "LENS 1: AUTH / AUTHZ"
run "service_role key outside server-only code" \
    "service_role gives full DB access and bypasses RLS. If it is reachable from the client bundle, anyone can do anything." \
    "service_role|SUPABASE_SERVICE_ROLE|serviceRole"

run "Supabase client created in a route/action" \
    "Confirm it uses the request user's session, not the service role, so RLS still applies." \
    "createServerClient|createClient\("

run "middleware present" \
    "Read middleware for fail-open: a try/catch that returns next() on error lets a broken auth check pass everyone through. Check the matcher covers protected paths." \
    "NextResponse\.next|export (async )?function middleware"

# RLS coverage. Reads repo SQL only; the Supabase dashboard is the real source of
# truth (RLS can be enabled there and not in repo migrations), so this is a lead.
check "RLS coverage on tables created in repo SQL" \
      "RLS is the real data boundary in Supabase. A table created without 'enable row level security' is open to the anon/authenticated key UNLESS RLS was set in the dashboard. Confirm every MISSING table below has RLS enabled in the Supabase dashboard."
sql_files="$(
  if command -v rg >/dev/null 2>&1; then
    rg -l -S -g '!node_modules' -g '!.next' -g '!.git' -g '*.sql' 'create table' "$ROOT" 2>/dev/null
  else
    grep -rliE --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=.git --include='*.sql' 'create table' "$ROOT" 2>/dev/null
  fi
)"
if [ -z "$sql_files" ]; then
  printf '  (no .sql with CREATE TABLE found) RLS cannot be verified from code.\n'
  printf '  Confirm every user-data table has RLS enabled in the Supabase dashboard.\n'
else
  all_sql="$(printf '%s\n' "$sql_files" | while IFS= read -r f; do [ -f "$f" ] && cat "$f"; done | tr 'A-Z' 'a-z')"
  created="$(printf '%s' "$all_sql" | grep -oE 'create table[[:space:]]+(if not exists[[:space:]]+)?(public\.)?[a-z0-9_]+' | sed -E 's/.*[[:space:]]//; s/^public\.//' | sort -u)"
  rls_on="$(printf '%s' "$all_sql" | grep -oE 'alter table[[:space:]]+(public\.)?[a-z0-9_]+[[:space:]]+enable row level security' | sed -E 's/^alter table[[:space:]]+//; s/[[:space:]]+enable.*//; s/^public\.//' | sort -u)"
  missing="$(comm -23 <(printf '%s\n' "$created") <(printf '%s\n' "$rls_on") | sed '/^$/d')"
  if [ -z "$missing" ]; then
    printf '  OK: every CREATE TABLE in repo SQL has a matching ENABLE ROW LEVEL SECURITY.\n'
  else
    printf '%s\n' "$missing" | while IFS= read -r t; do
      [ -n "$t" ] && printf '  MISSING %s (no ENABLE ROW LEVEL SECURITY in repo SQL; confirm in dashboard)\n' "$t"
    done
  fi
fi

run "mass assignment: a client object written straight to the DB" \
    "A write that takes the request body/object directly (.update(body), .insert({ ...body }), .upsert(req.body)) lets a user set columns they must not control: role, is_pro, plan, credits. Confirm the written fields are an explicit allow-list, not the raw body." \
    "\.(insert|update|upsert)\([[:space:]{]*(\.\.\.|body|req\.body|payload|parsed|formData)"

run "Supabase Storage usage" \
    "A public bucket exposes every user's files to anyone with the URL, and uploads with no size/type limit are a cost and abuse vector. Confirm buckets holding user data are private, that storage.objects has owner-scoped RLS, and that uploads are bounded." \
    "createBucket|storage\.from\(|\.upload\(|public:[[:space:]]*true"

# File-level negative check: a mutating API route handler that authenticates by
# the session cookie and has no Origin/Referer check or CSRF token is CSRF-prone.
# Bearer / API-key handlers (the browser does not send those cross-site) and
# Server Actions (Next applies same-origin protection) are excluded.
check "route handlers exposed to CSRF" \
      "Any file listed EXPOSED is an app/api or pages/api route handler with a mutating method (POST/PUT/PATCH/DELETE), authenticated by the Supabase session cookie, with no Origin/Referer check and no CSRF token. Add a same-origin (Origin/Referer) check or a CSRF token, or move the mutation to a Server Action. A lead: confirm by reading the handler."
csrf_method='export[[:space:]]+(async[[:space:]]+)?function[[:space:]]+(POST|PUT|PATCH|DELETE)|export[[:space:]]+const[[:space:]]+(POST|PUT|PATCH|DELETE)'
csrf_path='[/\\]app[/\\]api[/\\](.*[/\\])?route\.(ts|tsx|js|jsx|mjs|cjs)$|[/\\]pages[/\\]api[/\\]'
csrf_candidates="$(
  if command -v rg >/dev/null 2>&1; then
    rg -l -g '!node_modules' -g '!.next' -g '!dist' -g '!build' -g '!.git' "$csrf_method" "$ROOT" 2>/dev/null
  else
    grep -rlE --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=dist --exclude-dir=build --exclude-dir=.git "$csrf_method" "$ROOT" 2>/dev/null
  fi
)"
csrf_exposed="$(printf '%s\n' "$csrf_candidates" | while IFS= read -r f; do
  [ -f "$f" ] || continue
  printf '%s' "$f" | grep -qE "$csrf_path" || continue                                 # API route handler only
  grep -qE "['\"]use server['\"]" "$f" 2>/dev/null && continue                          # Server Action: Next protects it
  grep -qiE 'authorization|bearer|x-api-key|api[_-]?key|apikey' "$f" 2>/dev/null && continue   # header/bearer auth: not CSRF-prone
  grep -qE 'createServerClient|cookies\(|getUser|getSession' "$f" 2>/dev/null || continue       # require cookie-session auth
  grep -qiE "get\(['\"](origin|referer)|headers\.(origin|referer)|csrf[-_]?token|csrf\(" "$f" 2>/dev/null && continue  # already checks Origin/Referer or uses a CSRF token
  printf '%s\n' "$f"
done)"
if [ -z "$csrf_exposed" ]; then
  printf '  (no cookie-auth mutating route handler without an Origin/Referer check)\n'
else
  printf '%s\n' "$csrf_exposed" | sed 's|^|  EXPOSED |; s|$| (cookie-auth mutation, no Origin/Referer check or CSRF token)|'
fi

run "getSession used for a trust decision" \
    "In server code that decides access, prefer getUser (it revalidates the token with Supabase). getSession reads the cookie and can be stale or spoofed in some setups." \
    "getSession"

# File-level negative check: files that use .from(...) but show no owner filter
# anywhere in the file. A lead to read first; RLS may still cover the table.
check "queries with no obvious owner filter" \
      "Any file listed MISSING uses .from(...) but shows no user_id / auth.uid() / .eq() filter in the same file. If RLS is also missing on that table, it leaks rows."
from_files="$(
  if command -v rg >/dev/null 2>&1; then
    rg -l -S -g '!node_modules' -g '!.next' -g '!dist' -g '!build' -g '!.git' -g '!*.md' -g '!*.mdx' -g '!*.txt' '\.from\(' "$ROOT" 2>/dev/null
  else
    grep -rlE --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=dist --exclude-dir=build --exclude-dir=.git --exclude=*.md --exclude=*.mdx --exclude=*.txt '\.from\(' "$ROOT" 2>/dev/null
  fi
)"
if [ -z "$from_files" ]; then
  none
else
  from_missing="$(printf '%s\n' "$from_files" | while IFS= read -r f; do
    [ -f "$f" ] && { grep -qE 'user_id|auth\.uid|\.eq\(' "$f" 2>/dev/null || printf '%s\n' "$f"; }
  done)"
  if [ -z "$from_missing" ]; then
    printf '  (every file using .from also has a user_id/auth.uid/.eq filter)\n'
  else
    printf '%s\n' "$from_missing" | sed 's|^|  MISSING |; s|$| (.from used, no owner filter in file)|'
  fi
fi

# ---------------------------------------------------------------------------
section "LENS 2 + 3: ATOMICITY / IDEMPOTENCY (PAYMENTS)"
run "Stripe webhook handler" \
    "The handler MUST verify the signature with stripe.webhooks.constructEvent and MUST be idempotent (event.id dedupe). Confirm both." \
    "webhooks\.constructEvent|stripe-signature|checkout\.session\.completed|invoice\.paid"

# File-level negative check: find likely Stripe webhook handlers, then report
# any that never call constructEvent. A real signal, not a line-level guess.
check "webhook handler missing signature verification" \
      "Any file below is a likely Stripe webhook handler. If it is listed as MISSING, it never calls constructEvent and a forged 'paid' event can unlock paid features for free. P0."
webhook_files="$(
  if command -v rg >/dev/null 2>&1; then
    rg -l -S -g '!node_modules' -g '!.next' -g '!dist' -g '!build' -g '!.git' -g '!*.lock' -g '!*.md' -g '!*.mdx' -g '!*.txt' 'stripe-signature|checkout\.session\.completed|invoice\.paid|customer\.subscription' "$ROOT" 2>/dev/null
  else
    grep -rliE --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=dist --exclude-dir=build --exclude-dir=.git --exclude=*.md --exclude=*.mdx --exclude=*.txt 'stripe-signature|checkout\.session\.completed|invoice\.paid|customer\.subscription' "$ROOT" 2>/dev/null
  fi
)"
if [ -z "$webhook_files" ]; then
  none
else
  printf '%s\n' "$webhook_files" | while IFS= read -r f; do
    if grep -q 'constructEvent' "$f" 2>/dev/null; then
      printf '  OK      %s (verifies signature)\n' "$f"
    else
      printf '  MISSING %s (no constructEvent: verify it is forgeable)\n' "$f"
    fi
  done
fi

run "subscription / plan writes" \
    "Grant access from Stripe's source of truth (webhook or a fresh retrieve), not from a client-supplied 'success' redirect. Verify." \
    "subscription|is_pro|plan|entitlement|grant|upgrade"

# ---------------------------------------------------------------------------
section "LENS 5: INPUT VALIDATION / INJECTION / SSRF"
run "dangerouslySetInnerHTML" \
    "Unsanitized HTML is stored or reflected XSS. Confirm the content is sanitized or trusted." \
    "dangerouslySetInnerHTML"

run "outbound fetch with a variable URL" \
    "If the URL comes from user input, this is SSRF: a user can make your server hit internal addresses. Verify the host is allow-listed." \
    "fetch\((req|request|body|params|searchParams|input|url)"

run "open redirect from user input" \
    "A redirect whose target comes from the request (?next=, ?redirect=, returnTo) lets an attacker bounce a just-authenticated user to a phishing site under your domain's trust. Confirm the target is a relative path or an allow-listed host." \
    "redirect\([[:space:]]*(req|request|searchParams|params|query|body|url|next|returnTo|callbackUrl|redirectTo)"

run "eval / dynamic exec" \
    "eval and child_process with interpolated input is remote code execution waiting to happen." \
    "eval\(|child_process|exec\(|execSync"

run "missing input schema validation" \
    "Routes that parse a body but never validate it (no zod/yup/valibot parse) trust whatever the client sends." \
    "\.parse\(|safeParse|z\.object|yup\.|valibot"

# ---------------------------------------------------------------------------
section "LENS 6: CONFIG DRIFT / SECRETS"
run "secret-looking value exposed to the client" \
    "Anything prefixed NEXT_PUBLIC_ ships in the browser bundle. A secret/key/token there is public." \
    "NEXT_PUBLIC_[A-Z_]*(SECRET|KEY|TOKEN|PASSWORD|SERVICE)"

run "secret logged" \
    "console.log of a key/secret/token leaks it into server logs and error trackers." \
    "console\.(log|error|warn)\(.*(secret|token|key|password|service_role)"

run "wide-open CORS" \
    "Access-Control-Allow-Origin: * on an authenticated API lets any site call it with the user's context." \
    "Access-Control-Allow-Origin.*\*|cors\(\)"

# ---------------------------------------------------------------------------
section "LENS 4 + 7: DEGRADED MODE / ABUSE / COST"
run "rate limiting present?" \
    "If this prints nothing, there is likely NO rate limiting. Public routes, auth, and any LLM/email call need it or a single user can run up the bill." \
    "ratelimit|rateLimit|upstash|Ratelimit|express-rate-limit"

run "metered/paid external calls" \
    "Every match is a cost surface. Confirm it is behind auth AND a rate limit AND a per-user quota, or an anonymous user can drain your credits." \
    "openai|anthropic|resend|sendgrid|nodemailer|s3\.|put_object|generateContent"

run "quota / usage counters" \
    "Read these for read-then-write races: check quota, then increment in two steps lets concurrent requests both pass. Use an atomic RPC or a DB constraint." \
    "usage|quota|credits|remaining|count\b"

# ---------------------------------------------------------------------------
printf '\n========== END ==========\n'
echo "Next: open the reference file for each lens with candidates and confirm by reading the code."
