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
# LENS 8 is conditional: it runs only when the app looks multi-tenant. Otherwise
# it prints one line and emits no findings, so single-tenant apps (the majority)
# see no noise.
files_matching() { # files_matching "<pattern>" -> candidate file paths
  if command -v rg >/dev/null 2>&1; then
    rg -l -S -g '!node_modules' -g '!.next' -g '!dist' -g '!build' -g '!.git' -g '!*.lock' -g '!*.md' -g '!*.mdx' -g '!*.txt' "$1" "$ROOT" 2>/dev/null
  else
    grep -rliE --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=dist --exclude-dir=build --exclude-dir=.git --exclude=*.md --exclude=*.mdx --exclude=*.txt "$1" "$ROOT" 2>/dev/null
  fi
}
mt_signal() { [ -n "$(hits "$1")" ]; }
MULTITENANT=0
if mt_signal 'org_id|tenant_id|workspace_id' \
   || mt_signal 'agency_domains|custom_domains|customDomains|addDomain|removeDomain|resolveTenant|getTenantByHost' \
   || mt_signal 'subdomain' \
   || mt_signal 'create table[[:space:]]+(if not exists[[:space:]]+)?(public\.)?(orgs?|organizations?|tenants?|agenc(y|ies)|workspaces?)'; then
  MULTITENANT=1
fi

if [ "$MULTITENANT" -eq 0 ]; then
  printf '\nLens 8 (tenant isolation): single-tenant app, not applicable\n'
else
  section "LENS 8: TENANT ISOLATION (multi-tenant only)"

  # 8.1 session cookie scoped to a parent domain (lead, high signal)
  check "8.1 session cookie scoped to a parent domain" \
        "An auth cookie with a parent (leading-dot) domain attribute is shared across every tenant subdomain, enabling cross-tenant session theft. Each file below sets a cookie and includes a domain attribute. Confirm it is not the auth cookie on a parent domain."
  c81_files="$(files_matching 'cookies\(\)\.set|cookieStore\.set|cookies\.set|createServerClient|sb-')"
  c81="$(printf '%s\n' "$c81_files" | while IFS= read -r f; do
    [ -f "$f" ] || continue
    grep -niE "domain:[[:space:]]*[\"'][^\"']*\.[^\"']+[\"']" "$f" 2>/dev/null | sed "s|^|$f:|"
  done)"
  if [ -z "$c81" ]; then
    printf '  cookies appear host-only (OK)\n'
  else
    printf '%s\n' "$c81" | sed 's|^|  LEAD |; s|$| (cookie with a domain attribute; confirm it is not the auth cookie on a parent domain)|'
  fi

  # 8.2 tenant header trusted from the inbound request (file-level negative)
  check "8.2 tenant header trusted from the inbound request" \
        "A request handler that reads a tenant header from the incoming request without stripping it first lets an attacker forge it and switch tenants. A file is OK only if it unconditionally deletes the inbound tenant header."
  th_files="$(files_matching "x-[a-z0-9-]*tenant|headers\.get\([\"'][^\"']*tenant|set\([\"']x-[a-z0-9-]*tenant")"
  if [ -z "$th_files" ]; then
    printf '  (no file references a tenant header)\n'
  else
    printf '%s\n' "$th_files" | while IFS= read -r f; do
      [ -f "$f" ] || continue
      if grep -qiE "\.delete\([\"'][^\"']*tenant|headers\.delete\(" "$f" 2>/dev/null; then
        printf '  OK      %s (strips inbound tenant header)\n' "$f"
      else
        printf '  MISSING %s (trusts inbound tenant header, verify it is stripped)\n' "$f"
      fi
    done
  fi

  # 8.3 subdomain or domain creation without a reserved-name deny-list (lead)
  check "8.3 subdomain or domain creation without a reserved-name deny-list" \
        "A tenant could claim a reserved name (admin, api, www, the brand). A creation path with no reserved-name deny-list in the same file is a lead."
  dom_files="$(files_matching 'subdomain|agency_domains|custom_domains|domains')"
  d83="$(printf '%s\n' "$dom_files" | while IFS= read -r f; do
    [ -f "$f" ] || continue
    case "$f" in *.sql) continue;; esac
    # A creation path is an insert/upsert into a domains table or a subdomain write.
    # We require the write, so the bare word "subdomain" in a comment is not a hit.
    is_create=0
    { grep -qiE '\.(insert|upsert)\(' "$f" 2>/dev/null && grep -qiE 'agency_domains|custom_domains|domains|subdomain' "$f" 2>/dev/null; } && is_create=1
    [ "$is_create" -eq 1 ] || continue
    printf 'CAND %s\n' "$f"
    grep -qiE 'reserved|denylist|deny[_-]?list|blocklist|block[_-]?list' "$f" 2>/dev/null && continue
    grep -qiE "[\"'](admin|www|api|app|mail|static|assets|root)[\"'][,[:space:]]+[\"'](admin|www|api|app|mail|static|assets|root)[\"']" "$f" 2>/dev/null && continue
    printf 'LEAD %s\n' "$f"
  done)"
  cand_count="$(printf '%s\n' "$d83" | grep -c '^CAND ')"
  leads="$(printf '%s\n' "$d83" | sed -n 's|^LEAD ||p')"
  if [ "$cand_count" -eq 0 ]; then
    printf '  (no subdomain or domain creation path found)\n'
  elif [ -z "$leads" ]; then
    printf '  (subdomain or domain creation paths all have a reserved-name guard)\n'
  else
    printf '%s\n' "$leads" | sed 's|^|  LEAD |; s|$| (subdomain/domain creation with no reserved-name deny-list in file)|'
  fi

  # 8.4 tenant scoping pointer (agent read, no hard verdict)
  check "8.4 tenant scoping (read instruction, no verdict)" \
        "Tenant-owned tables must scope by the org or tenant key, not by user_id alone. This is confirmed by reading, not by grep."
  printf '  Verify every tenant-owned table scopes by the org or tenant key in its RLS policy, not by user_id alone. Confirm by reading the policies, ideally against the live database.\n'

  # 8.5 domain not deprovisioned on downgrade (file-level negative)
  check "8.5 domain not deprovisioned on downgrade" \
        "A cancelled tenant that keeps its custom domain is a paid feature for free and an orphaned domain. A subscription.deleted handler with no domain teardown is MISSING."
  subdel_files="$(files_matching 'customer\.subscription\.deleted|subscription\.deleted')"
  if [ -z "$subdel_files" ]; then
    printf '  (no subscription.deleted handler found)\n'
  else
    printf '%s\n' "$subdel_files" | while IFS= read -r f; do
      [ -f "$f" ] || continue
      if grep -qiE 'removeDomain|deprovision|disableDomain|invalidateTenant|agency_domains|custom_domains|status[^=]*disabled|delete[^;]*domain|teardown' "$f" 2>/dev/null; then
        printf '  OK      %s (references domain teardown on cancellation)\n' "$f"
      else
        printf '  MISSING %s (subscription cancellation does not deprovision the tenant domain)\n' "$f"
      fi
    done
  fi

  # 8.6 white-label content (cross-reference to Lens 5, no new grep)
  check "8.6 white-label content (cross-reference to Lens 5)" \
        "Tenant-controlled branding and custom-domain verification overlap Lens 5. No new grep here."
  printf '  Tenant-supplied branding (logo, color, HTML) and custom-domain verification are covered by Lens 5: confirm the color is strictly validated, no raw tenant HTML or CSS reaches the page, and custom-domain verification never fetches an attacker-supplied URL (SSRF).\n'
fi

# ---------------------------------------------------------------------------
printf '\n========== END ==========\n'
echo "Next: open the reference file for each lens with candidates and confirm by reading the code."
