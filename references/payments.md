# Payments (Lenses 2, 3, and part of 4)

The second most common P0: a user gets paid access without paying, or pays and
never gets access, because the app trusts the wrong source of truth or processes
the same event twice.

Contents:
1. Webhook signature verification
2. Webhook idempotency
3. Source of truth for access
4. Checkout and guest-checkout races
5. Downgrades, cancellations, refunds
6. Stripe degraded mode

## 1. Webhook signature verification

Stripe tells your app about payments by POSTing webhook events. If the handler
does not verify the signature, anyone who knows the URL can POST a fake
"payment succeeded" event and unlock paid features for free.

How to verify:
* The handler reads the raw request body (not parsed JSON) and the
  `stripe-signature` header.
* It calls `stripe.webhooks.constructEvent(rawBody, signature, webhookSecret)`
  and rejects anything that does not verify, before any business logic.
* The `webhookSecret` comes from env and is the secret for the correct
  environment (see config drift: test vs live secrets differ).

In Next.js App Router, the raw body matters: `await req.text()` gives the raw
string. Parsing with `req.json()` first will break signature verification, and a
handler that "fixed" that by skipping verification is the vulnerability.

## 2. Webhook idempotency

Stripe delivers events at least once, which means sometimes more than once, and
also retries on any non-2xx response. If the handler grants a month of credits
or sends an email every time it sees `invoice.paid`, duplicates cause
double-grants, double-emails, or double-charges in your own logic.

How to verify:
* The handler records processed `event.id`s (a table with a unique constraint on
  event id is the simplest) and skips events it has already handled.
* The grant itself is idempotent where possible: set state to "pro until date X"
  rather than "add 30 days" each time.
* The handler returns 2xx quickly after recording the event, so Stripe does not
  retry a success.

## 3. Source of truth for access

The success redirect URL (`/success?session_id=...`) is controlled by the
browser and can be visited directly or replayed. Granting access because the
user landed on the success page is a P0: anyone can hit that URL.

How to verify:
* Access is granted from the verified webhook, or by re-fetching the session
  server-side from Stripe (`stripe.checkout.sessions.retrieve`) and checking
  `payment_status === 'paid'` before granting.
* The user's plan stored in your database is updated only from these trusted
  paths, never from a client request body that says `{ plan: 'pro' }`.

## 4. Checkout and guest-checkout races

Guest checkout (no account yet) and account-linking after payment are a common
race surface. The pattern to confirm: payment and account get linked exactly
once, even if the webhook and the post-checkout flow run concurrently or out of
order, and even if the webhook arrives before the user finishes creating their
account.

How to verify:
* Linking keys off a stable identifier (Stripe customer id or the email captured
  at checkout), not off request timing.
* Two concurrent requests cannot both create a subscription record. A unique
  constraint on (customer_id) or (user_id) in the database, or an atomic upsert,
  prevents the duplicate rather than hoping the timing works out.

## 5. Downgrades, cancellations, refunds

Granting access is the happy path everyone codes. Revoking it is the path that
silently rots. If `customer.subscription.deleted`,
`customer.subscription.updated` (to a canceled or past_due state), and refunds
are not handled, users keep paid access after they stop paying.

How to verify the handler reacts to:
* Subscription canceled or ended: revoke access at period end or immediately per
  your policy.
* Payment failed / past_due: the access policy is explicit, not accidental.
* Refund issued: access is reconsidered.

## 6. Stripe degraded mode

When the Stripe API is slow or down, the app should fail safe. Verify:
* Checkout failures show the user a clear retry path, not a charged-but-no-access
  limbo.
* The app never grants access on a timeout "just in case". A timeout is not a
  payment.
