# saas-preflight report template

ALWAYS produce the report in exactly this structure. Fill the brackets. Drop any
section that has no content rather than padding it.

---

# Pre-ship audit: [project name]

**Stack detected:** [Next.js App/Pages Router] + [Supabase] + [Stripe]
**Date:** [YYYY-MM-DD]

## Verdict

[One sentence: is this safe to ship or not, and the single most important thing
to fix first.]

**P0:** [n]  |  **P1:** [n]  |  **P2:** [n]  |  **P3:** [n]

## P0: Ship blockers

### [short title]
* **Lens:** [one of the 7]
* **Location:** [path/to/file.ts:LINE]
* **Impact:** [what an attacker or unlucky user can do, concretely]
* **Fix:** [remediation, in plain steps, no exploit code]

[repeat per P0 finding]

## P1: Fix this week

[same finding format]

## P2: Hardening

[same finding format, can be terser]

## P3: Hygiene

[same finding format, one line each is fine]

## Clean lenses

[List the lenses that came back clean, one line each. This is not filler: it
tells the reader what was actually checked and found solid.]
* Auth / authz: [clean / see findings above]
* Atomicity: ...
* Idempotency: ...
* Degraded mode: ...
* Input validation: ...
* Config drift: ...
* Abuse / cost: ...

## How this was checked

[Two or three sentences: scanner run for leads, then each lens verified by
reading the actual code. Note any area you could not verify, for example RLS
policies if the database migrations were not in the repo, and say so plainly.]
