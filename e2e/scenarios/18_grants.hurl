# 18_grants.hurl — grant lifecycle round-trip + L4 customer
# attribution under grant-routed license creation.
#
# Flow:
#   1. Vendor (grantor) signs up
#   2. Vendor creates a product
#   3. Grantee signs up (a separate account)
#   4. Vendor issues a grant to the grantee for the product
#      with capabilities LICENSE_CREATE, LICENSE_READ,
#      CUSTOMER_CREATE, CUSTOMER_READ.
#   5. Grantee accepts the grant (status transitions to active)
#   6. Grantee creates a license under the grant using an inline
#      customer `dave@example.com`.
#   7. Assertions on the resulting license attribution:
#      - grant_id matches the issued grant
#      - created_by_account_id matches the grantee
#      - account_id matches the vendor (grantor)
#      - customer_id is populated
#   8. Grantor sees Dave in /v1/customers with
#      created_by_account_id == grantee_account_id.
#   9. Grantee sees Dave in /v1/grants/:id/customers but is blocked
#      from GET /v1/customers/:dave_id directly (404 — no leak).
#  10. Vendor issues a SECOND grant WITHOUT CUSTOMER_CREATE to
#      test the negative capability path:
#      - Inline-customer license creation → 403 grant_capability_missing.
#      - Attaching dave via customer_id still needs CUSTOMER_READ,
#        also missing → 403.
#  11. Vendor issues a THIRD grant with LICENSE_CREATE + CUSTOMER_READ
#      only, and the grantee successfully attaches dave via
#      customer_id (attach path only needs CUSTOMER_READ) → 201.
#
# Terminology: "vendor" = grantor (issuer), "grantee" = recipient.

# Step 1: vendor signup
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Vendor Co",
  "email": "e2e-vendor@test.com",
  "password": "password123"
}

HTTP 201
[Captures]
vendor_token: jsonpath "$.access_token"
vendor_account_id: jsonpath "$.account.id"

# Step 2: vendor creates a product
POST {{base_url}}/v1/products
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "name": "Widget Pro",
  "slug": "widget-pro"
}

HTTP 201
[Captures]
product_id: jsonpath "$.id"

# Step 3: grantee signup
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Grantee Co",
  "email": "e2e-grantee@test.com",
  "password": "password123"
}

HTTP 201
[Captures]
grantee_token: jsonpath "$.access_token"
grantee_account_id: jsonpath "$.account.id"

# Step 4: vendor issues a grant to the grantee for the product
#         with the full customer-capable capability set.
POST {{base_url}}/v1/accounts/{{vendor_account_id}}/grants
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "grantee_account_id": "{{grantee_account_id}}",
  "product_id": "{{product_id}}",
  "capabilities": ["LICENSE_CREATE", "LICENSE_READ", "CUSTOMER_CREATE", "CUSTOMER_READ"]
}

HTTP 201
[Asserts]
jsonpath "$.status" == "pending"
jsonpath "$.grantor_account_id" == "{{vendor_account_id}}"
jsonpath "$.grantee_account_id" == "{{grantee_account_id}}"
jsonpath "$.product_id" == "{{product_id}}"
[Captures]
grant_id: jsonpath "$.id"

# Step 5: grantee accepts the grant
POST {{base_url}}/v1/grants/{{grant_id}}/accept
Authorization: Bearer {{grantee_token}}

HTTP 200
[Asserts]
jsonpath "$.status" == "active"
jsonpath "$.accepted_at" exists

# Step 6: grantee creates a license under the grant with an
#         inline customer block. Requires CUSTOMER_CREATE on
#         the grant.
POST {{base_url}}/v1/grants/{{grant_id}}/licenses
Authorization: Bearer {{grantee_token}}
Content-Type: application/json
{
  "overrides": { "max_machines": 3 },
  "customer": {
    "email": "dave@example.com",
    "name": "Dave"
  }
}

HTTP 201
[Asserts]
jsonpath "$.license.id" exists
jsonpath "$.license.grant_id" == "{{grant_id}}"
jsonpath "$.license.created_by_account_id" == "{{grantee_account_id}}"
jsonpath "$.license.account_id" == "{{vendor_account_id}}"
jsonpath "$.license.customer_id" exists
jsonpath "$.license_key" exists
[Captures]
dave_id: jsonpath "$.license.customer_id"

# Step 7: vendor lists customers from the grantor side. Dave
#         appears, and created_by_account_id is the grantee
#         account (grant-attributed insert).
GET {{base_url}}/v1/customers
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].id" == "{{dave_id}}"
jsonpath "$.data[0].email" == "dave@example.com"
jsonpath "$.data[0].created_by_account_id" == "{{grantee_account_id}}"

# Step 8: grantee lists customers via the grant-scoped endpoint.
#         ResolveGrant flips TargetAccount to the grantor and the
#         handler filters by created_by_account_id=grantee — so
#         the grantee sees only Dave (the customer they created).
GET {{base_url}}/v1/grants/{{grant_id}}/customers
Authorization: Bearer {{grantee_token}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].id" == "{{dave_id}}"
jsonpath "$.data[0].email" == "dave@example.com"

# Step 9: grantee CANNOT read Dave via the standard
#         /v1/customers/:id endpoint — that runs under the
#         grantee's own RLS scope, where Dave does not exist.
#         Returns 404 (no cross-tenant existence leak).
GET {{base_url}}/v1/customers/{{dave_id}}
Authorization: Bearer {{grantee_token}}
HTTP 404

# Step 10: vendor issues a SECOND grant with only LICENSE_CREATE
#          + LICENSE_READ — no customer capabilities. We'll use
#          this to verify the negative path.
POST {{base_url}}/v1/accounts/{{vendor_account_id}}/grants
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "grantee_account_id": "{{grantee_account_id}}",
  "product_id": "{{product_id}}",
  "capabilities": ["LICENSE_CREATE", "LICENSE_READ"]
}
HTTP 201
[Captures]
grant_id_no_cust: jsonpath "$.id"

POST {{base_url}}/v1/grants/{{grant_id_no_cust}}/accept
Authorization: Bearer {{grantee_token}}
HTTP 200

# Step 10a: inline-customer license creation on the
#           no-customer grant → 403 grant_capability_missing.
POST {{base_url}}/v1/grants/{{grant_id_no_cust}}/licenses
Authorization: Bearer {{grantee_token}}
Content-Type: application/json
{
  "customer": {"email": "eve@example.com", "name": "Eve"}
}
HTTP 403
[Asserts]
jsonpath "$.error.code" == "grant_capability_missing"

# Step 10b: attach-existing via customer_id — needs CUSTOMER_READ,
#           which this grant also lacks. Also rejected.
POST {{base_url}}/v1/grants/{{grant_id_no_cust}}/licenses
Authorization: Bearer {{grantee_token}}
Content-Type: application/json
{
  "customer_id": "{{dave_id}}"
}
HTTP 403
[Asserts]
jsonpath "$.error.code" == "grant_capability_missing"

# Step 11: vendor issues a THIRD grant with LICENSE_CREATE +
#          CUSTOMER_READ only — enough to attach an existing
#          customer via customer_id, but not to create new ones.
POST {{base_url}}/v1/accounts/{{vendor_account_id}}/grants
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "grantee_account_id": "{{grantee_account_id}}",
  "product_id": "{{product_id}}",
  "capabilities": ["LICENSE_CREATE", "LICENSE_READ", "CUSTOMER_READ"]
}
HTTP 201
[Captures]
grant_id_read_only: jsonpath "$.id"

POST {{base_url}}/v1/grants/{{grant_id_read_only}}/accept
Authorization: Bearer {{grantee_token}}
HTTP 200

# Step 11a: attach path succeeds — 201.
POST {{base_url}}/v1/grants/{{grant_id_read_only}}/licenses
Authorization: Bearer {{grantee_token}}
Content-Type: application/json
{
  "customer_id": "{{dave_id}}"
}
HTTP 201
[Asserts]
jsonpath "$.license.customer_id" == "{{dave_id}}"
jsonpath "$.license.grant_id" == "{{grant_id_read_only}}"

# Step 11b: inline-customer on the read-only grant still fails —
#           CUSTOMER_READ doesn't authorize CREATE.
POST {{base_url}}/v1/grants/{{grant_id_read_only}}/licenses
Authorization: Bearer {{grantee_token}}
Content-Type: application/json
{
  "customer": {"email": "frank@example.com"}
}
HTTP 403
[Asserts]
jsonpath "$.error.code" == "grant_capability_missing"

# Step 12: grantee cannot revoke the grant by calling the
#          grantor-side route with their own token. The
#          requirePathAccountMatch check fires first and returns
#          422 validation_error (the path account_id does not
#          match the grantee's authenticated tenant).
POST {{base_url}}/v1/accounts/{{vendor_account_id}}/grants/{{grant_id_read_only}}/revoke
Authorization: Bearer {{grantee_token}}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# Step 13: grantor suspends grant_id_read_only. Response is the
#          full Grant with status=suspended.
POST {{base_url}}/v1/accounts/{{vendor_account_id}}/grants/{{grant_id_read_only}}/suspend
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{grant_id_read_only}}"
jsonpath "$.status" == "suspended"

# Step 14: grantee can no longer use the suspended grant — the
#          ResolveGrant middleware rejects with grant_not_active (422)
#          before the handler runs.
POST {{base_url}}/v1/grants/{{grant_id_read_only}}/licenses
Authorization: Bearer {{grantee_token}}
Content-Type: application/json
{
  "customer_id": "{{dave_id}}"
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "grant_not_active"

# Step 15: grantor revokes grant_id_read_only. Terminal transition;
#          the response shows status=revoked.
POST {{base_url}}/v1/accounts/{{vendor_account_id}}/grants/{{grant_id_read_only}}/revoke
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{grant_id_read_only}}"
jsonpath "$.status" == "revoked"

# Step 16: revoking an already-revoked grant is rejected with
#          validation_error (the service guards the terminal
#          transition with ErrValidationError).
POST {{base_url}}/v1/accounts/{{vendor_account_id}}/grants/{{grant_id_read_only}}/revoke
Authorization: Bearer {{vendor_token}}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# Step 17: vendor lists grants issued from their account.
#          After Steps 4, 11, 13 the vendor has issued three grants
#          (active, active, revoked). Sharing v2 default hides terminal
#          statuses, so only two appear. Asking for include_terminal=true
#          surfaces the revoked one as well — matrix tested in Step 27.
GET {{base_url}}/v1/accounts/{{vendor_account_id}}/grants
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 2
jsonpath "$.has_more" == false
jsonpath "$.data[*].grantor_account_id" contains "{{vendor_account_id}}"
jsonpath "$.data[*].id" not contains "{{grant_id_read_only}}"

# Step 17a: include_terminal=true reveals the revoked grant too.
GET {{base_url}}/v1/accounts/{{vendor_account_id}}/grants?include_terminal=true
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 3
jsonpath "$.data[*].id" contains "{{grant_id_read_only}}"

# Step 18: grantee lists grants received. Same default — only the two
#          non-terminal grants come back.
GET {{base_url}}/v1/grants/received
Authorization: Bearer {{grantee_token}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 2
jsonpath "$.has_more" == false
jsonpath "$.data[*].grantee_account_id" contains "{{grantee_account_id}}"

# Step 19: single-grant fetch is readable by both parties.
GET {{base_url}}/v1/grants/{{grant_id}}
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{grant_id}}"
jsonpath "$.grantor_account_id" == "{{vendor_account_id}}"

GET {{base_url}}/v1/grants/{{grant_id}}
Authorization: Bearer {{grantee_token}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{grant_id}}"
jsonpath "$.grantee_account_id" == "{{grantee_account_id}}"

# Step 20: unknown grant id → 404 (no existence leak for non-parties
#          either; this uses a random UUID the caller is not party to).
GET {{base_url}}/v1/grants/00000000-0000-0000-0000-000000000000
Authorization: Bearer {{vendor_token}}
HTTP 404
[Asserts]
jsonpath "$.error.code" == "grant_not_found"

# Step 21: path account mismatch on grantor-list → validation_error.
#          The grantee tries to list grants under the vendor's path.
GET {{base_url}}/v1/accounts/{{vendor_account_id}}/grants
Authorization: Bearer {{grantee_token}}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# =========================================================
# Sharing v2 flows — Leave, PATCH, Reinstate, Filters, Usage.
# Each flow issues a fresh grant so state preconditions are
# independent. `grant_id` (from Step 4) stays active and retains
# Dave's license so later flows can exercise usage counters and
# filters without disturbing Step 6's assertions.
# =========================================================

# =========================================================
# Step 22: Leave flow
#   - vendor issues grant_leave with full customer capabilities
#   - grantee accepts
#   - grantee creates customer Leaf + license under the grant
#   - grantee calls POST /v1/grants/:id/leave
#   - vendor still sees Leaf attributed to grantee_account_id
#   - grantee's received-grants?status=active excludes grant_leave
# =========================================================

POST {{base_url}}/v1/accounts/{{vendor_account_id}}/grants
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "grantee_account_id": "{{grantee_account_id}}",
  "product_id": "{{product_id}}",
  "capabilities": ["LICENSE_CREATE", "LICENSE_READ", "CUSTOMER_CREATE", "CUSTOMER_READ"]
}
HTTP 201
[Captures]
grant_leave_id: jsonpath "$.id"

POST {{base_url}}/v1/grants/{{grant_leave_id}}/accept
Authorization: Bearer {{grantee_token}}
HTTP 200
[Asserts]
jsonpath "$.status" == "active"

POST {{base_url}}/v1/grants/{{grant_leave_id}}/licenses
Authorization: Bearer {{grantee_token}}
Content-Type: application/json
{
  "customer": {"email": "leaf@example.com", "name": "Leaf"}
}
HTTP 201
[Captures]
leaf_license_id: jsonpath "$.license.id"
leaf_customer_id: jsonpath "$.license.customer_id"

# Grantee walks away.
POST {{base_url}}/v1/grants/{{grant_leave_id}}/leave
Authorization: Bearer {{grantee_token}}
HTTP 200
[Asserts]
jsonpath "$.status" == "left"

# Vendor sees the grant as 'left'. Grantee embedding survives.
GET {{base_url}}/v1/grants/{{grant_leave_id}}
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.status" == "left"
jsonpath "$.grantee_account.id" == "{{grantee_account_id}}"
jsonpath "$.grantee_account.slug" exists

# Vendor still owns Leaf under their tenant, and the
# created_by_account summary points back at the grantee.
GET {{base_url}}/v1/customers/{{leaf_customer_id}}
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{leaf_customer_id}}"
jsonpath "$.email" == "leaf@example.com"
jsonpath "$.created_by_account_id" == "{{grantee_account_id}}"
jsonpath "$.created_by_account.id" == "{{grantee_account_id}}"
jsonpath "$.created_by_account.slug" exists

# Grantee's status=active filter excludes the left grant.
# We avoid asserting overall data shape — the grantee still holds
# grant_id and grant_id_no_cust in active — just assert the left
# grant is absent from the active slice.
GET {{base_url}}/v1/accounts/{{grantee_account_id}}/received-grants?status=active
Authorization: Bearer {{grantee_token}}
HTTP 200
[Asserts]
jsonpath "$.data[*].id" not contains "{{grant_leave_id}}"
jsonpath "$.data[*].status" not contains "left"

# Even with include_terminal=true, a status=active filter excludes
# the left grant — status filter wins over include_terminal. With
# status=left, however, the grantee sees it.
GET {{base_url}}/v1/accounts/{{grantee_account_id}}/received-grants?status=left&include_terminal=true
Authorization: Bearer {{grantee_token}}
HTTP 200
[Asserts]
jsonpath "$.data[*].id" contains "{{grant_leave_id}}"

# =========================================================
# Step 23: PATCH flow — update capabilities + label on a fresh
# grant; confirm response shape and grant.updated audit event.
# =========================================================

POST {{base_url}}/v1/accounts/{{vendor_account_id}}/grants
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "grantee_account_id": "{{grantee_account_id}}",
  "product_id": "{{product_id}}",
  "capabilities": ["LICENSE_CREATE", "LICENSE_READ"],
  "label": "Initial label"
}
HTTP 201
[Captures]
grant_patch_id: jsonpath "$.id"

PATCH {{base_url}}/v1/accounts/{{vendor_account_id}}/grants/{{grant_patch_id}}
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "capabilities": ["LICENSE_READ", "MACHINE_READ"],
  "label": "Edited via e2e"
}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{grant_patch_id}}"
jsonpath "$.capabilities" count == 2
jsonpath "$.capabilities" contains "LICENSE_READ"
jsonpath "$.capabilities" contains "MACHINE_READ"
jsonpath "$.capabilities" not contains "LICENSE_CREATE"
jsonpath "$.label" == "Edited via e2e"

# Audit trail shows grant.updated referencing this grant.
GET {{base_url}}/v1/events?resource_type=grant&resource_id={{grant_patch_id}}
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.data[*].event_type" contains "grant.updated"
jsonpath "$.data[*].resource_id" contains "{{grant_patch_id}}"

# Clearing the label with explicit null drops it from the response.
PATCH {{base_url}}/v1/accounts/{{vendor_account_id}}/grants/{{grant_patch_id}}
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "label": null
}
HTTP 200
[Asserts]
jsonpath "$.label" not exists

# Grantees never see grantor-only annotations. Scrubbing enforces
# label/metadata are omitted — this was covered by scrubGrantForReader
# at the handler layer. Re-set the label as grantor, then fetch as grantee.
PATCH {{base_url}}/v1/accounts/{{vendor_account_id}}/grants/{{grant_patch_id}}
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "label": "Private to vendor"
}
HTTP 200
[Asserts]
jsonpath "$.label" == "Private to vendor"

GET {{base_url}}/v1/grants/{{grant_patch_id}}
Authorization: Bearer {{grantee_token}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{grant_patch_id}}"
jsonpath "$.label" not exists

# =========================================================
# Step 24: Reinstate flow — a fresh grant suspended and then
# flipped back to active. Post-reinstate the grantee can issue
# a license again via the grant-routed endpoint.
# =========================================================

POST {{base_url}}/v1/accounts/{{vendor_account_id}}/grants
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "grantee_account_id": "{{grantee_account_id}}",
  "product_id": "{{product_id}}",
  "capabilities": ["LICENSE_CREATE", "LICENSE_READ", "CUSTOMER_READ"]
}
HTTP 201
[Captures]
grant_reinstate_id: jsonpath "$.id"

POST {{base_url}}/v1/grants/{{grant_reinstate_id}}/accept
Authorization: Bearer {{grantee_token}}
HTTP 200

POST {{base_url}}/v1/accounts/{{vendor_account_id}}/grants/{{grant_reinstate_id}}/suspend
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.status" == "suspended"

# While suspended, grant-routed license creation is blocked by
# ResolveGrant → grant_not_active (422).
POST {{base_url}}/v1/grants/{{grant_reinstate_id}}/licenses
Authorization: Bearer {{grantee_token}}
Content-Type: application/json
{
  "customer_id": "{{dave_id}}"
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "grant_not_active"

# Reinstate — status flips back to active.
POST {{base_url}}/v1/accounts/{{vendor_account_id}}/grants/{{grant_reinstate_id}}/reinstate
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{grant_reinstate_id}}"
jsonpath "$.status" == "active"

# Grantee can issue licenses under the grant once more.
POST {{base_url}}/v1/grants/{{grant_reinstate_id}}/licenses
Authorization: Bearer {{grantee_token}}
Content-Type: application/json
{
  "customer_id": "{{dave_id}}"
}
HTTP 201
[Asserts]
jsonpath "$.license.grant_id" == "{{grant_reinstate_id}}"
jsonpath "$.license.customer_id" == "{{dave_id}}"

# Reinstating a non-suspended (now active) grant → grant_not_suspended.
POST {{base_url}}/v1/accounts/{{vendor_account_id}}/grants/{{grant_reinstate_id}}/reinstate
Authorization: Bearer {{vendor_token}}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "grant_not_suspended"

# =========================================================
# Step 25: Filter matrix — product_id + status CSV + include_terminal.
# Vendor now has: grant_id (active), grant_id_no_cust (active),
# grant_id_read_only (revoked), grant_leave (left), grant_patch (active),
# grant_reinstate (active). All share the same product_id.
# =========================================================

# product_id=product_id restricts to this product (all six grants match).
# status=active,pending narrows to active ones (the 4 active grants).
GET {{base_url}}/v1/accounts/{{vendor_account_id}}/grants?product_id={{product_id}}&status=active,pending
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 4
jsonpath "$.data[*].product_id" contains "{{product_id}}"
jsonpath "$.data[*].status" not contains "revoked"
jsonpath "$.data[*].status" not contains "left"
jsonpath "$.data[*].status" not contains "suspended"

# include_terminal=true surfaces every grant regardless of state
# (6 total — 4 active, 1 revoked, 1 left).
GET {{base_url}}/v1/accounts/{{vendor_account_id}}/grants?include_terminal=true
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 6
jsonpath "$.data[*].id" contains "{{grant_id_read_only}}"
jsonpath "$.data[*].id" contains "{{grant_leave_id}}"
jsonpath "$.data[*].status" contains "revoked"
jsonpath "$.data[*].status" contains "left"

# Non-matching product_id returns an empty page.
GET {{base_url}}/v1/accounts/{{vendor_account_id}}/grants?product_id=00000000-0000-0000-0000-000000000000
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 0

# =========================================================
# Step 26: Usage counters — single-grant GET includes Usage,
# list GETs never do. grant_id carries one license (Dave) from Step 6.
# Single-grant fetches go through /v1/grants/:id (readable by both
# grantor and grantee); no account-scoped single-grant route exists.
# =========================================================

GET {{base_url}}/v1/grants/{{grant_id}}
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{grant_id}}"
jsonpath "$.usage" exists
jsonpath "$.usage.licenses_total" >= 1
jsonpath "$.usage.licenses_this_month" >= 1
jsonpath "$.usage.customers_total" >= 1

# Grantee's single-grant fetch also returns a Usage block, though the
# count fields are computed under the grantee's own RLS scope — the
# grantor's licenses table is invisible to the grantee, so the counts
# read as 0. The Usage field MUST still be present for API consistency.
GET {{base_url}}/v1/grants/{{grant_id}}
Authorization: Bearer {{grantee_token}}
HTTP 200
[Asserts]
jsonpath "$.usage" exists

# List responses never include Usage — too costly at N×3 counts.
GET {{base_url}}/v1/accounts/{{vendor_account_id}}/grants
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.data[0].usage" not exists

GET {{base_url}}/v1/grants/received
Authorization: Bearer {{grantee_token}}
HTTP 200
[Asserts]
jsonpath "$.data[0].usage" not exists
