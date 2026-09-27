# Commercial Hosted Features

Commercial hosted builds add managed-SaaS capabilities on top of OSS: pricing
tiers, self-serve signup, usage limits, tenant email invites, outbound mail
adapters, SCIM 2.0 provisioning, and Stripe billing. All of it stays off unless
`TRUSTOPS_COMMERCIAL_HOSTED=1`.

## Enable hosted mode

```bash
export TRUSTOPS_COMMERCIAL_HOSTED=1
export TRUSTOPS_PUBLIC_URL=https://trustops.example.com
export TRUSTOPS_EMAIL_PROVIDER=log   # default: log-only (no SMTP)
```

Self-serve workspace creation:

```bash
export TRUSTOPS_SELF_SERVE_SIGNUP=1
export TRUSTOPS_SIGNUP_SECRET=<long-random-secret>   # callers send it as X-TrustOps-Signup-Secret
```

Signup fails closed: with no `TRUSTOPS_SIGNUP_SECRET`, `POST /api/v1/signup`
returns 403 unless you explicitly set `TRUSTOPS_ALLOW_OPEN_SIGNUP=1` to accept
unauthenticated workspace creation.

SAML SSO for hosted tenants is configured as in
[Server auth](SERVER_AUTH.md#saml). Only SP-initiated logins are accepted by
default; set `TRUSTOPS_SAML_ALLOW_IDP_INITIATED=true` to accept IdP-initiated
logins. Consumed assertion IDs are stored in the shared application database,
so a replay is rejected whichever replica receives it.

Optional SCIM 2.0 provisioning (Enterprise tier). Enable it, then have a tenant
admin issue a SCIM token (see [SCIM](#scim)):

```bash
export TRUSTOPS_SCIM_ENABLED=1
# Optional: map IdP groups to TrustOps roles (highest privilege wins).
export TRUSTOPS_SCIM_ROLE_MAP='{"TrustOps Admins": "admin", "TrustOps Auditors": "auditor"}'
export TRUSTOPS_SCIM_DEFAULT_ROLE=read_only   # role for users in no mapped group
```

`TRUSTOPS_SCIM_BEARER_TOKEN` + `TRUSTOPS_SCIM_TENANT_SLUG` still authenticate as a
deprecated single-tenant fallback; prefer per-tenant tokens.

## Invite API

| Method | Path                     | Auth              | Description                |
| ------ | ------------------------ | ----------------- | -------------------------- |
| `GET`  | `/api/v1/invites`        | `auth_admin`      | List tenant invites        |
| `POST` | `/api/v1/invites`        | `auth_admin`      | Create invite + send email |
| `POST` | `/api/v1/invites/accept` | none (token body) | Accept pending invite      |

Create body:

```json
{ "email": "user@company.com", "role": "contributor" }
```

Accept body:

```json
{ "token": "<invite-token-from-email>", "display_name": "Alex" }
```

When `TRUSTOPS_COMMERCIAL_HOSTED` is unset, invite routes return **501 Not Implemented**.

## Pricing and signup

| Method | Path                       | Auth                                | Description                |
| ------ | -------------------------- | ----------------------------------- | -------------------------- |
| `GET`  | `/api/v1/platform/pricing` | none                                | Tier list + limits (gated) |
| `POST` | `/api/v1/signup`           | optional `X-TrustOps-Signup-Secret` | Create tenant + admin user |
| `GET`  | `/api/v1/platform/usage`   | `auth_admin`                        | Plan tier, usage vs limits |

These routes return **501 Not Implemented** unless `TRUSTOPS_COMMERCIAL_HOSTED=1`.
Tier definitions and dollar amounts are operator-managed and not published in the
OSS repository or console.

## Email delivery

| `TRUSTOPS_EMAIL_PROVIDER` | Behavior                                                       |
| ------------------------- | -------------------------------------------------------------- |
| `log` (default)           | Log `{to, subject}` at INFO — safe for dev                     |
| other                     | Extend `security_lakehouse.commercial.email` with SES/SendGrid |

## SCIM

SCIM endpoints return raw SCIM JSON (`application/scim+json`, no TrustOps
envelope) and SCIM error objects (`urn:ietf:params:scim:api:messages:2.0:Error`
with `status` and, where relevant, `scimType`), which is what Okta and Entra ID
parse. Every `/api/v1/scim/v2/*` call except `ServiceProviderConfig` needs
`Authorization: Bearer <tenant SCIM token>`; the token selects the tenant, so a
token can never read or change another tenant's users or groups.

### Tokens (tenant admin, TrustOps API)

| Method   | Path                                | Description                                                 |
| -------- | ----------------------------------- | ----------------------------------------------------------- |
| `POST`   | `/api/v1/platform/scim/tokens`      | Issue a token (`{"name": "okta"}`); plaintext returned once |
| `GET`    | `/api/v1/platform/scim/tokens`      | List tokens: name, prefix, created, last used, revoked      |
| `DELETE` | `/api/v1/platform/scim/tokens/{id}` | Revoke                                                      |

Only a SHA-256 hash of each token is stored. Rotate by issuing a new token,
updating the IdP, then revoking the old one; both work until the revoke.
Admins manage the same tokens in the console under **Auth → SCIM
provisioning**; the panel is hidden when SCIM is disabled (501).

### Users and groups

| Method                       | Path                                    | Notes                                                                               |
| ---------------------------- | --------------------------------------- | ----------------------------------------------------------------------------------- |
| `GET`                        | `/api/v1/scim/v2/ServiceProviderConfig` | patch + filter supported; bulk, sort, etag, changePassword not                      |
| `GET`                        | `/api/v1/scim/v2/Users`                 | `filter=userName eq "…"` or `externalId eq "…"`; `startIndex`/`count` (max 200)     |
| `POST`                       | `/api/v1/scim/v2/Users`                 | `409 uniqueness` for an existing userName; re-creating a deleted user restores it   |
| `GET`/`PUT`/`PATCH`          | `/api/v1/scim/v2/Users/{id}`            | PATCH accepts path and path-less operations (Okta and Entra ID shapes)              |
| `DELETE`                     | `/api/v1/scim/v2/Users/{id}`            | Soft delete: deactivated, removed from groups, then 404 to SCIM; row kept for audit |
| `GET`/`POST`                 | `/api/v1/scim/v2/Groups`                | `filter=displayName eq "…"`; members must be users of the same tenant               |
| `GET`/`PUT`/`PATCH`/`DELETE` | `/api/v1/scim/v2/Groups/{id}`           | PATCH add/remove/replace `members`, including `members[value eq "…"]`               |

With `TRUSTOPS_SCIM_ROLE_MAP` set, every membership change recomputes the
affected users' roles: the highest-privilege mapped group wins, and a user in no
mapped group gets `TRUSTOPS_SCIM_DEFAULT_ROLE`. Without a role map, groups are
stored but never change roles. This has been tested against the RFC 7644 shapes
Okta and Entra ID send, not yet against a live IdP tenant.

## Billing (Stripe)

Self-serve plans are bought through Stripe Checkout and managed in the Stripe
customer portal, so card data never reaches TrustOps. TrustOps calls the Stripe
REST API directly (no SDK) and keeps no card or bank data.

```bash
export TRUSTOPS_BILLING_ENABLED=1
export TRUSTOPS_STRIPE_SECRET_KEY_FILE=/run/secrets/stripe_secret_key   # or TRUSTOPS_STRIPE_SECRET_KEY
export TRUSTOPS_STRIPE_WEBHOOK_SECRET_FILE=/run/secrets/stripe_whsec     # comma-separated while rolling
export TRUSTOPS_STRIPE_PRICE_STARTER=price_...
export TRUSTOPS_STRIPE_PRICE_TEAM=price_...
export TRUSTOPS_STRIPE_PRICE_BUSINESS=price_...
export TRUSTOPS_PUBLIC_URL=https://trustops.example.com                 # Checkout/portal return URLs
export TRUSTOPS_BILLING_GRACE_DAYS=7                                     # past-due grace before read-only
```

Enterprise stays sales-led: it has no self-serve price, and tenants that never
subscribed (for example invoiced contracts) are not restricted.

| Method | Path                             | Auth        | Description                                                  |
| ------ | -------------------------------- | ----------- | ------------------------------------------------------------ |
| `GET`  | `/api/v1/billing`                | any member  | Plan, subscription status, access state, period end          |
| `POST` | `/api/v1/billing/checkout`       | admin       | `{"plan": "team"}` → Stripe Checkout URL (subscription mode) |
| `POST` | `/api/v1/billing/portal`         | admin       | Stripe customer portal URL (payment method, plan, cancel)    |
| `POST` | `/api/v1/billing/stripe/webhook` | Stripe sig. | Register in Stripe for the events below                      |

The console shows the same state under **Auth → Billing**: plan, access badge,
grace or read-only notices, plan checkout buttons (before a Stripe customer
exists), and **Manage billing** for the portal. Checkout and portal return to
`/console/auth/`. The panel is hidden when billing is disabled (501).

Webhook events handled: `checkout.session.completed`,
`customer.subscription.created`/`updated`/`deleted`/`paused`/`resumed`,
`invoice.paid`, `invoice.payment_failed`.

- **Verification.** `Stripe-Signature` is checked with HMAC-SHA256 over
  `timestamp.body` (`v1` only, constant-time, 5-minute tolerance).
- **Idempotency.** Event ids are recorded after successful processing, so
  redeliveries apply once; a processing failure answers 5xx and Stripe retries.
- **Ordering.** Stripe does not guarantee event order, so each event re-reads
  the customer's latest subscription from the API and applies that, never the
  event snapshot.
- **Plan state.** The subscription's price sets the tenant's `plan_tier`, which
  the usage limits above enforce.

| Subscription status                                  | Access                                                 |
| ---------------------------------------------------- | ------------------------------------------------------ |
| `active`, `trialing`, none                           | full                                                   |
| `past_due`, `incomplete`                             | full for `TRUSTOPS_BILLING_GRACE_DAYS`, then read-only |
| `canceled`, `unpaid`, `incomplete_expired`, `paused` | read-only                                              |

Read-only keeps every record and all reads; write scopes are removed at
authentication, so every write endpoint answers 403 with a pointer to the
billing portal. Admins can always reach `/api/v1/billing/*`, and SCIM keeps
working so identity-provider offboarding never stops.

## Database

Migration `0012_tenant_invites` adds the `tenant_invites` table.
Migration `0013_tenant_plan_tier` adds `tenants.plan_tier` for hosted limits.
Migration `0017_scim` adds `scim_tokens`, `scim_groups`, `scim_group_members`, and
`users.scim_external_id` / `users.scim_deleted_at`.
Migration `0018_billing` adds `tenant_billing` and `stripe_events`.

```bash
security-lakehouse db upgrade --lake build/lakehouse
```

## Related docs

- [Deployment](DEPLOYMENT.md) — OSS vs self-hosted positioning
- [HA read replicas](runbooks/HA_READ_REPLICAS.md) — single-writer lake + read replicas
- [Helm security guards](../deploy/README.md) — auth + replica guards
