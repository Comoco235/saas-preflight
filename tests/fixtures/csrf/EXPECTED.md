# CSRF check fixture

Run the scanner on this directory and read the
"route handlers exposed to CSRF" check. Exactly one file must be EXPOSED:

| File | Expected | Why |
|------|----------|-----|
| `app/api/note/route.ts` | **EXPOSED** | cookie-session auth, mutating, no Origin/Referer check |
| `app/api/ingest/route.ts` | not listed | Bearer-token auth — browser does not send it cross-site |
| `app/actions/notes.ts` | not listed | Server Action — Next applies same-origin protection |
| `app/api/comment/route.ts` | not listed | cookie auth but verifies the Origin header |

```bash
bash scripts/scan.sh tests/fixtures/csrf          # only app/api/note/route.ts EXPOSED
powershell -File scripts/scan.ps1 tests/fixtures/csrf
```

The bash and PowerShell scanners must produce the same single EXPOSED file.
