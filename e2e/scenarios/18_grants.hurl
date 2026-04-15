# 18_grants.hurl — grant lifecycle round-trip
#
# Flow:
#   1. Vendor (grantor) signs up
#   2. Vendor creates a product
#   3. Grantee signs up (a separate account)
#   4. Vendor issues a grant to the grantee for the product
#   5. Grantee accepts the grant (status transitions to active)
#   6. Grantee creates a license under the grant
#   7. Assertions on the resulting license attribution:
#      - grant_id matches the issued grant
#      - created_by_account_id matches the grantee
#      - account_id matches the vendor (grantor) — license lives in
#        the grantor's tenant space
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
POST {{base_url}}/v1/accounts/{{vendor_account_id}}/grants
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "grantee_account_id": "{{grantee_account_id}}",
  "product_id": "{{product_id}}",
  "capabilities": ["LICENSE_CREATE", "LICENSE_READ"]
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

# Step 6: grantee creates a license under the grant
POST {{base_url}}/v1/grants/{{grant_id}}/licenses
Authorization: Bearer {{grantee_token}}
Content-Type: application/json
{
  "overrides": { "max_machines": 3 },
  "licensee_email": "customer@example.com"
}

HTTP 201
[Asserts]
jsonpath "$.license.id" exists
jsonpath "$.license.grant_id" == "{{grant_id}}"
jsonpath "$.license.created_by_account_id" == "{{grantee_account_id}}"
jsonpath "$.license.account_id" == "{{vendor_account_id}}"
jsonpath "$.license_key" exists
