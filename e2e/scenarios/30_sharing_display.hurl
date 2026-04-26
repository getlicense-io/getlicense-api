# 30_sharing_display.hurl — Sharing v2 partner display + privacy scrubbing
#
# Covers:
#   - AccountSummary embed (grantor_account / grantee_account) on Grant reads
#   - grantor-only label/metadata scrubbed from grantee reads
#   - Customer responses carry created_by_account when grant-created
#   - GET /v1/accounts/:id returns AccountSummary for counterparty
#   - Stranger GET /v1/accounts/:id returns 404 (no existence leak)

# Step 1: vendor signup
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Display Vendor",
  "email": "e2e-dv-vendor@test.com",
  "password": "password123"
}

HTTP 201
[Captures]
vendor_token: jsonpath "$.access_token"
vendor_account_id: jsonpath "$.account.id"
vendor_slug: jsonpath "$.account.slug"

# Step 2: vendor creates a product
POST {{base_url}}/v1/products
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "name": "Display Widget",
  "slug": "display-widget"
}

HTTP 201
[Captures]
product_id: jsonpath "$.id"

# Step 3: grantee signup
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Display Partner",
  "email": "e2e-dv-partner@test.com",
  "password": "password123"
}

HTTP 201
[Captures]
grantee_token: jsonpath "$.access_token"
grantee_account_id: jsonpath "$.account.id"
grantee_slug: jsonpath "$.account.slug"

# Step 4: stranger signup (no relationship to vendor or grantee)
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Display Stranger",
  "email": "e2e-dv-stranger@test.com",
  "password": "password123"
}

HTTP 201
[Captures]
stranger_token: jsonpath "$.access_token"
stranger_account_id: jsonpath "$.account.id"

# Step 5: vendor issues a grant to grantee with label + metadata
POST {{base_url}}/v1/accounts/{{vendor_account_id}}/grants
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "grantee_account_id": "{{grantee_account_id}}",
  "product_id": "{{product_id}}",
  "capabilities": ["LICENSE_CREATE", "CUSTOMER_CREATE", "CUSTOMER_READ"]
}

HTTP 201
[Captures]
grant_id: jsonpath "$.id"

# Step 5a: PATCH to add label + metadata (grantor-only fields)
PATCH {{base_url}}/v1/accounts/{{vendor_account_id}}/grants/{{grant_id}}
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "label": "Display Partner integration",
  "metadata": {"internal_note": "vendor-only annotation"}
}

HTTP 200

# Step 6: grantee accepts
POST {{base_url}}/v1/grants/{{grant_id}}/accept
Authorization: Bearer {{grantee_token}}

HTTP 200

# Step 7: grantor reads the grant → sees grantee_account embed + own label/metadata
# Single-grant GET lives at /v1/grants/:grant_id (readable by both grantor and grantee).
GET {{base_url}}/v1/grants/{{grant_id}}
Authorization: Bearer {{vendor_token}}

HTTP 200
[Asserts]
jsonpath "$.grantor_account.id" == "{{vendor_account_id}}"
jsonpath "$.grantor_account.slug" == "{{vendor_slug}}"
jsonpath "$.grantee_account.id" == "{{grantee_account_id}}"
jsonpath "$.grantee_account.slug" == "{{grantee_slug}}"
jsonpath "$.grantee_account.name" == "Display Partner"
jsonpath "$.label" == "Display Partner integration"
jsonpath "$.metadata.internal_note" == "vendor-only annotation"

# Step 8: grantee reads the grant → sees grantor embed but label/metadata are scrubbed
GET {{base_url}}/v1/grants/{{grant_id}}
Authorization: Bearer {{grantee_token}}

HTTP 200
[Asserts]
jsonpath "$.grantor_account.id" == "{{vendor_account_id}}"
jsonpath "$.grantor_account.name" == "Display Vendor"
jsonpath "$.grantee_account.id" == "{{grantee_account_id}}"
jsonpath "$.label" not exists
# metadata — either absent or empty object; grantor-only either way
jsonpath "$.metadata.internal_note" not exists

# Step 9: grantee creates a license under the grant with inline customer.
# NOTE: product_id is derived server-side from the grant binding — the
# request body does NOT include it. Sending it would 422 under strict
# bind (PR-A.2).
POST {{base_url}}/v1/grants/{{grant_id}}/licenses
Authorization: Bearer {{grantee_token}}
Content-Type: application/json
{
  "customer": {
    "email": "display-customer@example.com",
    "name": "Display Customer"
  }
}

HTTP 201
[Captures]
customer_id: jsonpath "$.license.customer_id"

# Step 10: vendor sees the customer with created_by_account embed
GET {{base_url}}/v1/customers/{{customer_id}}
Authorization: Bearer {{vendor_token}}

HTTP 200
[Asserts]
jsonpath "$.created_by_account_id" == "{{grantee_account_id}}"
jsonpath "$.created_by_account.id" == "{{grantee_account_id}}"
jsonpath "$.created_by_account.slug" == "{{grantee_slug}}"
jsonpath "$.created_by_account.name" == "Display Partner"

# Step 11: vendor list /v1/customers also includes the embed
GET {{base_url}}/v1/customers
Authorization: Bearer {{vendor_token}}

HTTP 200
[Asserts]
jsonpath "$.data[0].created_by_account.slug" == "{{grantee_slug}}"

# Step 12: vendor can GET /v1/accounts/{grantee} (active grant counterparty)
GET {{base_url}}/v1/accounts/{{grantee_account_id}}
Authorization: Bearer {{vendor_token}}

HTTP 200
[Asserts]
jsonpath "$.id" == "{{grantee_account_id}}"
jsonpath "$.name" == "Display Partner"
jsonpath "$.slug" == "{{grantee_slug}}"
jsonpath "$.created_at" not exists

# Step 13: grantee can GET /v1/accounts/{vendor} (reverse counterparty)
GET {{base_url}}/v1/accounts/{{vendor_account_id}}
Authorization: Bearer {{grantee_token}}

HTTP 200
[Asserts]
jsonpath "$.id" == "{{vendor_account_id}}"
jsonpath "$.name" == "Display Vendor"
jsonpath "$.slug" == "{{vendor_slug}}"
jsonpath "$.created_at" not exists

# Step 14: stranger cannot GET vendor or grantee — 404 (no existence leak)
GET {{base_url}}/v1/accounts/{{vendor_account_id}}
Authorization: Bearer {{stranger_token}}

HTTP 404
[Asserts]
jsonpath "$.error.code" == "account_not_found"

GET {{base_url}}/v1/accounts/{{grantee_account_id}}
Authorization: Bearer {{stranger_token}}

HTTP 404
[Asserts]
jsonpath "$.error.code" == "account_not_found"

# Step 15: caller can GET their own account via the summary endpoint (membership path)
GET {{base_url}}/v1/accounts/{{stranger_account_id}}
Authorization: Bearer {{stranger_token}}

HTTP 200
[Asserts]
jsonpath "$.id" == "{{stranger_account_id}}"
jsonpath "$.name" == "Display Stranger"

# Step 16: vendor issues a grant-kind INVITATION to a fresh partner email
# (distinct from the direct-grant partner above). Added in Task 19 of
# frontend-unblock-batch to regression-guard the pre-create duplicate
# guard landed in Task 18.
POST {{base_url}}/v1/accounts/{{vendor_account_id}}/invitations
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "kind": "grant",
  "email": "e2e-dv-invitee@test.com",
  "grant_draft": {
    "product_id": "{{product_id}}",
    "capabilities": ["LICENSE_CREATE", "LICENSE_READ"]
  }
}

HTTP 201
[Asserts]
jsonpath "$.invitation.kind" == "grant"
jsonpath "$.invitation.email" == "e2e-dv-invitee@test.com"

# Step 17: duplicate guard — re-issuing the SAME (vendor, email, product)
# triple must reject with 409 invitation_already_exists. This exercises
# the "pending invitation exists" branch of the guard (nothing has accepted
# yet, so the grant-row branch is inactive).
POST {{base_url}}/v1/accounts/{{vendor_account_id}}/invitations
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "kind": "grant",
  "email": "e2e-dv-invitee@test.com",
  "grant_draft": {
    "product_id": "{{product_id}}",
    "capabilities": ["LICENSE_CREATE", "LICENSE_READ"]
  }
}

HTTP 409
[Asserts]
jsonpath "$.error.code" == "invitation_already_exists"

# Step 18: guard is keyed on (account, email, product) — NOT (account,
# email). Create a second product, then invite the SAME partner for that
# product. Must succeed with 201.
POST {{base_url}}/v1/products
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "name": "Display Widget 2",
  "slug": "display-widget-2"
}

HTTP 201
[Captures]
second_product_id: jsonpath "$.id"

POST {{base_url}}/v1/accounts/{{vendor_account_id}}/invitations
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "kind": "grant",
  "email": "e2e-dv-invitee@test.com",
  "grant_draft": {
    "product_id": "{{second_product_id}}",
    "capabilities": ["LICENSE_CREATE"]
  }
}

HTTP 201
[Asserts]
jsonpath "$.invitation.kind" == "grant"
jsonpath "$.invitation.email" == "e2e-dv-invitee@test.com"
