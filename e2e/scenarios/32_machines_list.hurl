# 32_machines_list.hurl — vendor lists machines for a license they own.
# Covers the Task 7 GET /v1/licenses/:id/machines route.

# --- Vendor signup ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Machines E2E Co",
  "email": "e2e-machines-vendor@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
vendor_token: jsonpath "$.access_token"
vendor_account_id: jsonpath "$.account.id"

# --- Create a product ---
POST {{base_url}}/v1/products
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{ "name": "Machines Widget", "slug": "machines-widget" }
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Create a license under the product ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{ "customer": { "email": "e2e-machines-buyer@test.com" } }
HTTP 201
[Captures]
license_id: jsonpath "$.license.id"

# --- Activate two machines ---
POST {{base_url}}/v1/licenses/{{license_id}}/activate
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{ "fingerprint": "fp-alpha", "hostname": "host-alpha" }
HTTP 201

POST {{base_url}}/v1/licenses/{{license_id}}/activate
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{ "fingerprint": "fp-beta", "hostname": "host-beta" }
HTTP 201

# --- List — both machines present ---
GET {{base_url}}/v1/licenses/{{license_id}}/machines
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 2
jsonpath "$.data[*].fingerprint" contains "fp-alpha"
jsonpath "$.data[*].fingerprint" contains "fp-beta"

# --- Filter status=active (both machines are active post-activation) ---
GET {{base_url}}/v1/licenses/{{license_id}}/machines?status=active
Authorization: Bearer {{vendor_token}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 2

# --- Invalid status -> 422 ---
GET {{base_url}}/v1/licenses/{{license_id}}/machines?status=zombie
Authorization: Bearer {{vendor_token}}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# --- Unknown license_id -> 404 ---
GET {{base_url}}/v1/licenses/00000000-0000-0000-0000-000000000000/machines
Authorization: Bearer {{vendor_token}}
HTTP 404
[Asserts]
jsonpath "$.error.code" == "license_not_found"
