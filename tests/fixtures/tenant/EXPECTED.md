# Lens 8 tenant-isolation fixture

This directory carries multi-tenant signals (an `agencies` table, `agency_domains`,
a `tenant_id` column, a `subdomain` column), so the Lens 8 activation gate opens
and the scanner prints the `LENS 8: TENANT ISOLATION (multi-tenant only)` section.

Run the scanner on this directory and read the Lens 8 section. Each detectable
check has one file that must be flagged and one that must not:

| Check | File | Expected |
|-------|------|----------|
| 8.1 cookie scope | `cookie-parent-domain.ts` | **LEAD** (cookie set with `domain: ".app.com"`) |
| 8.1 cookie scope | `cookie-host-only.ts` | not listed (host-only, no domain attribute) |
| 8.2 tenant header | `middleware-trusts-tenant-header.ts` | **MISSING** (reads `x-app-tenant`, no strip) |
| 8.2 tenant header | `middleware-strips-tenant-header.ts` | **OK** (unconditional `delete('x-app-tenant')`) |
| 8.3 reserved deny-list | `domain-create-no-denylist.ts` | **LEAD** (inserts a subdomain, no guard) |
| 8.3 reserved deny-list | `domain-create-with-denylist.ts` | not listed (reserved-name guard present) |
| 8.5 domain lifecycle | `webhook-no-domain-teardown.ts` | **MISSING** (cancellation sets plan free only) |
| 8.5 domain lifecycle | `webhook-with-domain-teardown.ts` | **OK** (cancellation removes the domain) |

8.4 and 8.6 print read pointers only (no verdict, no grep).

```bash
bash scripts/scan.sh tests/fixtures/tenant
powershell -File scripts/scan.ps1 tests/fixtures/tenant
```

The bash and PowerShell scanners must produce the same per-file verdicts. The
strip-then-reread case (`middleware-strips-tenant-header.ts`) stays OK, and the
external-teardown case (`webhook-with-domain-teardown.ts`) stays OK, so the two
known false positives do not fire.
