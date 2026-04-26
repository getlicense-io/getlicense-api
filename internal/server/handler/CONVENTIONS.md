# Handler conventions

## HTTP response status codes for mutation endpoints

We use the following rules consistently:

| Pattern | Status | Body |
|---|---|---|
| Create returns the new resource | `201 Created` | JSON of the created resource |
| Update returns the new state | `200 OK` | JSON of the updated resource |
| Delete / deactivate / no-echo mutations | `204 No Content` | Empty |
| Async / queued operation accepted | `202 Accepted` | Optional JSON envelope |

**Never** use `200 OK` with an empty body — return `204` instead. The
HTTP spec reserves `200` for responses that have a meaningful body.

Examples in this repo:
- `POST /v1/products` → 201 + Product
- `PATCH /v1/products/:id` → 200 + Product (the updated state is useful)
- `DELETE /v1/products/:id` → 204
- `POST /v1/policies/:id/entitlements` → 204 (attach is a write the
  client doesn't need echoed; they can `GET` to see the new set)

When in doubt, check the existing handler for the same resource family.

## Request body decoding

Use `bindStrict(c, &req)` in handlers (defined in `bind.go`). It
rejects requests with unknown JSON fields as 422 `validation_error`,
AND rejects bodies that contain trailing JSON content after the first
document (e.g. `{"a":1} {"b":2}`). Both checks catch client bugs
early and prevent silent drift between client and server.

Prefer `bindStrict` over the older `c.Bind().Body(&req)` for any new
handler. Older handlers are migrated incrementally to limit blast
radius — see git history for which endpoints have already migrated.

When migrating an existing handler, verify the OpenAPI request schema
documents EVERY field the handler reads. If clients have been sending
fields the spec doesn't list, switching to `bindStrict` will break
those callers — add the field to the spec OR keep `c.Bind().Body()`
until the spec catches up.

### Migration status (PR-A.2, post-second-round-review)

**Migrated (strict bind, rejects unknown fields):**

- `apikeys.go` — Create
- `customers.go` — Create, Update
- `entitlements.go` — Create, Update, AttachPolicyEntitlements,
  ReplacePolicyEntitlements, AttachLicenseEntitlements,
  ReplaceLicenseEntitlements
- `environments.go` — Create
- `grants.go` — Issue, CreateLicense
- `identity.go` — ActivateTOTP, DisableTOTP
- `invitations.go` — Create
- `licenses.go` — Create, BulkCreate, Activate, Deactivate, Update,
  AttachPolicy
- `policies.go` — Create, Update
- `products.go` — Create, Update
- `webhooks.go` — Create

**Deferred (still on `c.Bind().Body()`, lenient):**

- `auth.go` — Signup, Login, LoginTOTP, Refresh, Logout, Switch
  (6 sites). Public surface; the dashboard and library callers
  predate the strict-bind discipline and the OpenAPI spec for these
  paths has not been audited against actual payload shapes. A
  migration here without that audit could break login.
- `validate.go` — Validate (1 site). Public license validation is
  the most safety-critical surface in the API; only one field is
  documented (`license_key`) but partner SDKs may be sending
  forward-compatibility hints. Defer until the SDK fleet is audited.

The next pass migrates the deferred handlers after auditing each
request schema against the dashboard's and SDKs' actual payload
shapes. Until then, every NEW handler must use `bindStrict`.
