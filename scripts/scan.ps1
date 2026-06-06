#!/usr/bin/env pwsh
#
# saas-preflight scanner (PowerShell port of scan.sh)
#
# Prints candidate findings for a Next.js + Supabase + Stripe SaaS, grouped by
# the 7 audit lenses. Every line is a LEAD, not a verdict. Pattern search cannot
# prove a vulnerability: it misses real issues and flags safe code. Use the
# output to decide what to read, then confirm by reading the actual code.
#
# Usage: powershell -File scan.ps1 <path-to-repo>   (Windows PowerShell 5.1)
#        pwsh -File scan.ps1 <path-to-repo>         (PowerShell 7+)
# Read-only. Makes no changes and no network calls.

param([string]$Root = ".")

if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
  Write-Error "saas-preflight: '$Root' is not a directory."
  Write-Error "Usage: powershell -File scan.ps1 <path-to-repo>"
  exit 1
}
$rootFull = (Resolve-Path -LiteralPath $Root).Path

# Collect source/config files, pruning heavy dirs so we never walk node_modules.
$excludeDir = @('node_modules', '.next', '.git', 'dist', 'build', 'coverage', 'out')
$includeExt = '\.(ts|tsx|js|jsx|mjs|cjs|sql|json|prisma|graphql|svelte|vue|astro|env|ya?ml|toml|sh|bash|ps1|html|css|scss)$'

function Get-SourceFiles([string]$base) {
  $entries = Get-ChildItem -LiteralPath $base -Force -ErrorAction SilentlyContinue
  foreach ($e in $entries) {
    if ($e.PSIsContainer) {
      if ($excludeDir -notcontains $e.Name) { Get-SourceFiles $e.FullName }
    } elseif ($e.Name -notlike '*.lock') {
      if ($e.Name -match $includeExt -or $e.Name -match '^\.env') { $e }
    }
  }
}

$srcFiles = @(Get-SourceFiles $rootFull)

# Pre-read each file once (one ReadAllText, then split) so patterns are cheap.
$fileData = foreach ($f in $srcFiles) {
  try {
    $text = [System.IO.File]::ReadAllText($f.FullName)
    [pscustomobject]@{
      Rel   = $f.FullName.Substring($rootFull.Length).TrimStart('\', '/')
      Full  = $f.FullName
      Text  = $text
      Lines = ($text -split "\r?\n")
    }
  } catch { }
}

# Line-level search. -match is case-insensitive by default (like grep -i).
function Search-Hits([string]$pattern) {
  $out = New-Object System.Collections.Generic.List[string]
  foreach ($fd in $fileData) {
    for ($i = 0; $i -lt $fd.Lines.Count; $i++) {
      if ($fd.Lines[$i] -match $pattern) {
        $out.Add(("  {0}:{1}:{2}" -f $fd.Rel, ($i + 1), $fd.Lines[$i].Trim()))
      }
    }
  }
  return , $out
}

function Write-Section([string]$t) { ""; "========== $t ==========" }
function Write-Check([string]$label, [string]$why) { ""; "[$label]"; "  why: $why" }
function Write-None { "  (no candidates)" }

function Invoke-Run([string]$label, [string]$why, [string]$pattern) {
  Write-Check $label $why
  $hits = Search-Hits $pattern
  if ($hits.Count -gt 0) { $hits } else { Write-None }
}

"saas-preflight scan of: $rootFull"
"Every match below is a lead to verify by reading the code. Not a verdict."

# ---------------------------------------------------------------------------
Write-Section "LENS 1: AUTH / AUTHZ"
Invoke-Run "service_role key outside server-only code" `
  "service_role gives full DB access and bypasses RLS. If it is reachable from the client bundle, anyone can do anything." `
  'service_role|SUPABASE_SERVICE_ROLE|serviceRole'

Invoke-Run "Supabase client created in a route/action" `
  "Confirm it uses the request user's session, not the service role, so RLS still applies." `
  'createServerClient|createClient\('

Invoke-Run "middleware present" `
  "Read middleware for fail-open: a try/catch that returns next() on error lets a broken auth check pass everyone through. Check the matcher covers protected paths." `
  'NextResponse\.next|export (async )?function middleware'

# RLS coverage. Reads repo SQL only; the Supabase dashboard is the real source of
# truth (RLS can be enabled there and not in repo migrations), so this is a lead.
Write-Check "RLS coverage on tables created in repo SQL" `
  "RLS is the real data boundary in Supabase. A table created without 'enable row level security' is open to the anon/authenticated key UNLESS RLS was set in the dashboard. Confirm every MISSING table below has RLS enabled in the Supabase dashboard."
$sqlData = $fileData | Where-Object { $_.Full.ToLower().EndsWith('.sql') -and ($_.Text -match 'create table') }
if (-not $sqlData) {
  "  (no .sql with CREATE TABLE found) RLS cannot be verified from code."
  "  Confirm every user-data table has RLS enabled in the Supabase dashboard."
} else {
  $allSql = (($sqlData | ForEach-Object { $_.Text }) -join "`n").ToLower()
  $created = [regex]::Matches($allSql, 'create table\s+(?:if not exists\s+)?(?:public\.)?([a-z0-9_]+)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
  $rlsOn   = [regex]::Matches($allSql, 'alter table\s+(?:public\.)?([a-z0-9_]+)\s+enable row level security') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
  $missing = @($created | Where-Object { $_ -and ($rlsOn -notcontains $_) })
  if ($missing.Count -eq 0) {
    "  OK: every CREATE TABLE in repo SQL has a matching ENABLE ROW LEVEL SECURITY."
  } else {
    foreach ($t in $missing) { "  MISSING $t (no ENABLE ROW LEVEL SECURITY in repo SQL; confirm in dashboard)" }
  }
}

Invoke-Run "mass assignment: a client object written straight to the DB" `
  "A write that takes the request body/object directly (.update(body), .insert({ ...body }), .upsert(req.body)) lets a user set columns they must not control: role, is_pro, plan, credits. Confirm the written fields are an explicit allow-list, not the raw body." `
  '\.(insert|update|upsert)\([\s{]*(\.\.\.|body|req\.body|payload|parsed|formData)'

Invoke-Run "Supabase Storage usage" `
  "A public bucket exposes every user's files to anyone with the URL, and uploads with no size/type limit are a cost and abuse vector. Confirm buckets holding user data are private, that storage.objects has owner-scoped RLS, and that uploads are bounded." `
  'createBucket|storage\.from\(|\.upload\(|public:\s*true'

Invoke-Run "route handlers that mutate (CSRF)" `
  "POST/PUT/PATCH/DELETE route handlers that act on the session cookie are CSRF-exposed: Server Actions get Next's same-origin check, plain route handlers do not. Confirm an Origin/Sec-Fetch-Site check or a CSRF token, or route mutations through Server Actions." `
  'export\s+(async\s+)?function\s+(POST|PUT|PATCH|DELETE)|export\s+const\s+(POST|PUT|PATCH|DELETE)'

Invoke-Run "getSession used for a trust decision" `
  "In server code that decides access, prefer getUser (it revalidates the token with Supabase). getSession reads the cookie and can be stale or spoofed in some setups." `
  'getSession'

# File-level negative check: files that use .from(...) but show no owner filter.
Write-Check "queries with no obvious owner filter" `
  "Any file listed MISSING uses .from(...) but shows no user_id / auth.uid() / .eq() filter in the same file. If RLS is also missing on that table, it leaks rows."
$fromData = $fileData | Where-Object { $_.Text -match '\.from\(' }
if (-not $fromData) {
  Write-None
} else {
  $miss = @($fromData | Where-Object { -not ($_.Text -match 'user_id|auth\.uid|\.eq\(') })
  if ($miss.Count -eq 0) {
    "  (every file using .from also has a user_id/auth.uid/.eq filter)"
  } else {
    foreach ($fd in $miss) { "  MISSING $($fd.Rel) (.from used, no owner filter in file)" }
  }
}

# ---------------------------------------------------------------------------
Write-Section "LENS 2 + 3: ATOMICITY / IDEMPOTENCY (PAYMENTS)"
Invoke-Run "Stripe webhook handler" `
  "The handler MUST verify the signature with stripe.webhooks.constructEvent and MUST be idempotent (event.id dedupe). Confirm both." `
  'webhooks\.constructEvent|stripe-signature|checkout\.session\.completed|invoice\.paid'

Write-Check "webhook handler missing signature verification" `
  "Any file below is a likely Stripe webhook handler. If it is listed as MISSING, it never calls constructEvent and a forged 'paid' event can unlock paid features for free. P0."
$webhookData = $fileData | Where-Object { $_.Text -match 'stripe-signature|checkout\.session\.completed|invoice\.paid|customer\.subscription' }
if (-not $webhookData) {
  Write-None
} else {
  foreach ($fd in $webhookData) {
    if ($fd.Text -match 'constructEvent') { "  OK      $($fd.Rel) (verifies signature)" }
    else { "  MISSING $($fd.Rel) (no constructEvent: verify it is forgeable)" }
  }
}

Invoke-Run "subscription / plan writes" `
  "Grant access from Stripe's source of truth (webhook or a fresh retrieve), not from a client-supplied 'success' redirect. Verify." `
  'subscription|is_pro|plan|entitlement|grant|upgrade'

# ---------------------------------------------------------------------------
Write-Section "LENS 5: INPUT VALIDATION / INJECTION / SSRF"
Invoke-Run "dangerouslySetInnerHTML" `
  "Unsanitized HTML is stored or reflected XSS. Confirm the content is sanitized or trusted." `
  'dangerouslySetInnerHTML'

Invoke-Run "outbound fetch with a variable URL" `
  "If the URL comes from user input, this is SSRF: a user can make your server hit internal addresses. Verify the host is allow-listed." `
  'fetch\((req|request|body|params|searchParams|input|url)'

Invoke-Run "open redirect from user input" `
  "A redirect whose target comes from the request (?next=, ?redirect=, returnTo) lets an attacker bounce a just-authenticated user to a phishing site under your domain's trust. Confirm the target is a relative path or an allow-listed host." `
  'redirect\(\s*(req|request|searchParams|params|query|body|url|next|returnTo|callbackUrl|redirectTo)'

Invoke-Run "eval / dynamic exec" `
  "eval and child_process with interpolated input is remote code execution waiting to happen." `
  'eval\(|child_process|exec\(|execSync'

Invoke-Run "missing input schema validation" `
  "Routes that parse a body but never validate it (no zod/yup/valibot parse) trust whatever the client sends." `
  '\.parse\(|safeParse|z\.object|yup\.|valibot'

# ---------------------------------------------------------------------------
Write-Section "LENS 6: CONFIG DRIFT / SECRETS"
Invoke-Run "secret-looking value exposed to the client" `
  "Anything prefixed NEXT_PUBLIC_ ships in the browser bundle. A secret/key/token there is public." `
  'NEXT_PUBLIC_[A-Z_]*(SECRET|KEY|TOKEN|PASSWORD|SERVICE)'

Invoke-Run "secret logged" `
  "console.log of a key/secret/token leaks it into server logs and error trackers." `
  'console\.(log|error|warn)\(.*(secret|token|key|password|service_role)'

Invoke-Run "wide-open CORS" `
  "Access-Control-Allow-Origin: * on an authenticated API lets any site call it with the user's context." `
  'Access-Control-Allow-Origin.*\*|cors\(\)'

# ---------------------------------------------------------------------------
Write-Section "LENS 4 + 7: DEGRADED MODE / ABUSE / COST"
Invoke-Run "rate limiting present?" `
  "If this prints nothing, there is likely NO rate limiting. Public routes, auth, and any LLM/email call need it or a single user can run up the bill." `
  'ratelimit|rateLimit|upstash|Ratelimit|express-rate-limit'

Invoke-Run "metered/paid external calls" `
  "Every match is a cost surface. Confirm it is behind auth AND a rate limit AND a per-user quota, or an anonymous user can drain your credits." `
  'openai|anthropic|resend|sendgrid|nodemailer|s3\.|put_object|generateContent'

Invoke-Run "quota / usage counters" `
  "Read these for read-then-write races: check quota, then increment in two steps lets concurrent requests both pass. Use an atomic RPC or a DB constraint." `
  'usage|quota|credits|remaining|count\b'

# ---------------------------------------------------------------------------
""
"========== END =========="
"Next: open the reference file for each lens with candidates and confirm by reading the code."
