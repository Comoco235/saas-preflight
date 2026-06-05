# Abuse, validation, config (Lenses 5, 6, 7, and part of 4)

The findings here are rarely a single dramatic P0, but they are how a SaaS gets
drained, defaced, or broken in production: an anonymous user running up your
LLM bill, a secret shipped to the browser, a quota that two concurrent requests
both slip past.

Contents:
1. Input validation
2. SSRF (server-side request forgery)
3. XSS and injection
4. Rate limiting
5. Quota races
6. Unbounded cost
7. Secrets and config drift
8. CORS

## 1. Input validation

AI-generated routes often parse a request body and use it directly. Untrusted
input must be validated and bounded before it touches the database, the
filesystem, an outbound request, or an LLM prompt.

How to verify, per route and action:
* The body is parsed through a schema (zod, valibot, yup) that rejects unexpected
  shapes, not just cast with `as`.
* String fields have length limits. An unbounded text field is a cost and abuse
  vector (huge payloads, prompt stuffing).
* Numbers, enums, and ids are constrained to expected ranges and values.

A type assertion like `body as CreateThing` is not validation. TypeScript types
vanish at runtime. Flag routes that trust the body's shape with no runtime check.

## 2. SSRF

If the server makes an outbound `fetch` to a URL that came from the user, a user
can point it at internal addresses (cloud metadata endpoints, localhost
services, internal APIs) and read responses they should never see.

How to verify, for every outbound request built from user input:
* The destination host is checked against an allow-list, or the feature does not
  accept arbitrary URLs at all.
* Redirects are not followed blindly to internal hosts.
* The response is not reflected back to the user in a way that turns the server
  into a proxy.

## 3. XSS and injection

* `dangerouslySetInnerHTML` with any content that originated from a user is
  stored or reflected XSS unless sanitized. Confirm sanitization or trusted
  source.
* Raw SQL built by string concatenation is SQL injection. With Supabase, prefer
  the query builder or parameterized RPC. Flag any string-interpolated SQL.
* User-controlled values placed into CSS, style attributes, or `<style>` blocks
  can break layout or exfiltrate via CSS. Brand-color and theme inputs are a
  common spot: validate they match a strict color format before use.

## 4. Rate limiting

If the scanner found no rate-limiting library, the app very likely has none.
Without it, a single client can hammer auth, signup, password reset, and any
expensive endpoint.

How to verify the following are rate limited, per IP and per user where relevant:
* Auth endpoints (login, signup, password reset, magic link, OTP).
* Any endpoint that calls a paid API or sends email.
* Public write endpoints (contact forms, comment creation).

A simple fixed-window limiter (for example via Upstash) on the hot endpoints is
enough for a P2 to be closed. The absence of any limiter on a paid-API endpoint
is closer to P1, see cost below.

## 5. Quota races

The freemium pattern "check remaining quota, then do the work, then decrement"
is a read-then-write race. Two concurrent requests both read "1 remaining", both
proceed, and the user gets two for the price of one. At scale, free users get
unlimited usage.

How to verify:
* The decrement is atomic: a single SQL statement or RPC that decrements and
  returns the new value, or a check constraint that refuses to go below zero, so
  the database serializes the contention.
* The check and the consume are not two separate round trips with application
  logic in between.

## 6. Unbounded cost

Every call to an LLM, email provider, image generation, or storage write costs
money. The question for each: can an anonymous or free user trigger it without
limit?

How to verify each cost surface is behind all three of:
* Authentication (who is calling).
* Rate limiting (how often).
* A per-user quota or hard cap (how much total), enforced atomically.

Missing all three on an LLM endpoint is how a SaaS wakes up to a four-figure
bill from one abusive user overnight.

## 7. Secrets and config drift

* `NEXT_PUBLIC_` prefixed variables are bundled into the browser. A secret there
  is public to every visitor. Service role keys, Stripe secret keys, and API
  tokens must never carry that prefix.
* Secrets must not be logged. A `console.log` of a token leaks it into server
  logs and any connected error tracker.
* Test vs live drift: Stripe price ids, publishable and secret keys, and webhook
  secrets differ between test and live. A live deploy still pointing at test
  values, or a webhook verifying against the wrong secret, breaks payments
  silently. Confirm env values are environment-correct.
* Redirect and callback URLs (auth confirmation, OAuth, Stripe success/cancel)
  must match the deployed domain, or confirmation and checkout return flows 404.

## 8. CORS

`Access-Control-Allow-Origin: *` on an authenticated API lets any website call
it in the context of a logged-in user's browser. Verify CORS is scoped to your
own origins on any route that returns user data or performs actions.
