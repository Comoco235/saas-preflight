---
name: saas-preflight
description: >-
  Audit a vibe-coded or AI-generated SaaS for security and payment failures
  before it ships, focused on the Next.js + Supabase + Stripe stack. Use this
  whenever the user is about to deploy, launch, or "ship" a web app that handles
  authentication, user data, or payments. Trigger on phrases like "is my app
  secure", "can someone read other users' data", "is my Stripe integration
  safe", "will someone get a free subscription", "review my SaaS before launch",
  "I'm going to production", or any review of API routes, server actions,
  Supabase RLS policies, Stripe webhooks, or middleware in a SaaS, even if the
  user never says the word "audit". Prefer this skill over an ad-hoc code read
  whenever real users or real money are about to touch the code.
---

# saas-preflight

A pre-ship security and payment audit for SaaS built fast with AI, on the
Next.js + Supabase + Stripe stack. It finds the failure modes that AI-generated
code ships by default: a stranger reading another user's data, a stranger
getting a paid plan for free, a webhook that silently fails so subscriptions
never activate, a middleware that fails open.

This skill is **defensive only**. It detects weaknesses in the user's own
codebase so they can be fixed. It never writes exploit code, never produces an
attack payload, and never targets a system the user does not own.

## The 7 lenses

Every finding maps to one of these lenses. They are the spine of the audit. Run
through all seven; do not stop at the first scary thing.

1. **Auth / authz**: Is every protected route, server action, and data query
   actually checking who the caller is and whether they own the thing they touch?
2. **Atomicity**: Can a half-finished operation leave money charged but access
   not granted, or two writes that should be one?
3. **Idempotency**: If a webhook or request is delivered twice, does the app do
   the work twice (double-grant, double-charge, double-email)?
4. **Degraded mode**: When Stripe, Supabase, or an email provider is slow or
   down, does the app fail safe or fail open?
5. **Input validation**: Is untrusted input validated and bounded before it
   hits the database, the filesystem, an outbound fetch, or the DOM?
6. **Config drift**: Do secrets, price IDs, redirect URLs, and CORS differ
   between environments in a way that breaks prod or leaks keys to the client?
7. **Abuse / cost**: Can an anonymous user run up the bill (LLM calls, emails,
   storage, compute) or exhaust quotas through races?

## Workflow

Follow this order. The scanner is an optional accelerator, not a gate: if it
cannot run on this machine, do the triage by reading the code yourself and
continue. Never report a grep hit as a confirmed vulnerability without reading
the actual code first.

### 1. Scope the repo

Find the project root and confirm the stack. Look for `package.json` (Next.js),
a `supabase/` directory or `@supabase/*` imports, and `stripe` usage. Note
whether the app uses the App Router (`app/`) or Pages Router (`pages/`), and
whether there are server actions, route handlers, or both. If the stack is not
Next.js + Supabase + Stripe, say so plainly and adapt: the 7 lenses still apply,
but the specific patterns in the reference files may not match.

### 2. Run the scanner (optional fast first pass)

The scanner gives candidate flags in seconds. It is a convenience, not a
requirement. The full audit comes from reading the code against the 7 lenses, so
if the script does not run on this machine, do not stop: go to step 3 and do the
triage yourself by reading the code.

Run it like this:

```bash
bash scripts/scan.sh <path-to-repo>
```

On Windows it runs through Git Bash (bundled with Git for Windows) or WSL, with
a Windows-style path, for example `bash scripts/scan.sh C:/Users/me/my-app`. If
no bash is available or the script errors, say so in one line and proceed
without it. The audit is never blocked by a missing scanner.

When it does run, it prints candidate findings grouped by lens. Treat every line
as a lead, not a verdict. Grep cannot prove a vulnerability and will both miss
real issues and flag safe code. Its job is to point your reading.

If you skip the scanner, your step 3 reading must cover all 7 lenses from
scratch rather than starting from flags. Use the reference files as your
checklist so nothing is missed.

### 3. Verify against the reference files

For each lens with candidate flags, and for each lens regardless if the app is
about to handle real money or real users, read the matching reference and verify
by reading the actual code:

* `references/auth-and-isolation.md`: Lens 1. Server-side auth on routes and
  actions, middleware fail-open, Supabase RLS, object ownership (IDOR).
* `references/payments.md`: Lenses 2, 3, partly 4. Stripe webhook signature and
  idempotency, subscription state as source of truth, checkout and guest-checkout
  races, downgrades and refunds.
* `references/abuse-validation-config.md`: Lenses 5, 6, 7, partly 4. Input
  validation, SSRF, rate limiting, quota races, unbounded cost, secrets and env,
  CORS, degraded-mode behavior.

Read a reference only when you reach its lens. This keeps context lean.

A finding is real only if you can point to the exact file and line and explain
the concrete consequence ("an authenticated user can read row X belonging to
another user because the query filters by nothing"). If you cannot, downgrade it
to a note or drop it.

### 4. Write the report

Produce the report using `assets/REPORT_TEMPLATE.md` exactly. Prioritize by
severity. For every finding give: the lens, the file and line, what an attacker
or unlucky user can do, and a concrete fix. Write the fix as remediation, never
as a working exploit.

## Severity model

* **P0: Ship blocker.** Any authenticated or anonymous user can read or write
  data that is not theirs, or obtain paid access without paying, or cause money
  loss. Fix before shipping, full stop.
* **P1: Fix this week.** Exploitable but needs a specific condition (a known
  id, a race window, a misconfigured env). Real risk, slightly higher bar.
* **P2: Hardening.** Not directly exploitable today but one refactor away from
  P1, or missing defense in depth (no rate limit, no idempotency key yet).
* **P3: Hygiene.** Secrets in logs, dead config, weak CORS on a non-sensitive
  route, TODOs near auth.

If you are unsure between two levels, state the assumption that decides it rather
than guessing silently.

## Output discipline

* Lead with the count by severity and the single most important thing to fix.
* No filler. Every finding earns its place.
* If a whole lens is clean, say so in one line. Clean lenses build trust.
* Never invent a finding to pad the report. If the repo is solid, say it is
  solid and stop.