# Single-tenant activation fixture

This mini repo has no multi-tenant signals: no org, tenant, agency, or workspace
table, no custom domains, no Host based routing. Running the scanner on it, the
Lens 8 activation gate must stay shut.

Expected: the scanner prints exactly one Lens 8 line and emits no Lens 8 finding:

```
Lens 8 (tenant isolation): single-tenant app, not applicable
```

```bash
bash scripts/scan.sh tests/fixtures/single-tenant
powershell -File scripts/scan.ps1 tests/fixtures/single-tenant
```

The bash and PowerShell scanners must both print the not-applicable line and no
8.1 to 8.6 output. This proves Lens 8 creates no noise for single-tenant apps.
