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
  SEARCH() { rg -n --no-heading -S -g '!node_modules' -g '!.next' -g '!dist' -g '!build' -g '!*.lock' "$@" "$ROOT" 2>/dev/null; }
else
  SEARCH() {
    # last arg is the pattern when called as SEARCH "pattern"; emulate rg -n -S
    grep -rniE --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=dist --exclude-dir=build "$1" "$ROOT" 2>/dev/null
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

run "queries with no obvious owner filter" \
    "A .from(...).select() with no .eq('user_id', ...) or equivalent leaks rows if RLS is also missing. Verify RLS on the table." \
    "\.from\("

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
    rg -l -S -g '!node_modules' -g '!.next' 'stripe-signature|checkout\.session\.completed|invoice\.paid|customer\.subscription' "$ROOT" 2>/dev/null
  else
    grep -rliE --exclude-dir=node_modules --exclude-dir=.next 'stripe-signature|checkout\.session\.completed|invoice\.paid|customer\.subscription' "$ROOT" 2>/dev/null
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
