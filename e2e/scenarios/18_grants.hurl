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
