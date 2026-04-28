# 32_machines_list_grant.hurl — grantee lists machines for a license
# they created under their grant. Asserts the grantee cannot see
# machines on a sibling license OUTSIDE the grant (404, not 403).
# Covers the Task 8 grant-scoped machines route.

# --- Grantor (vendor) signup ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Grantor Machines Co",
  "email": "e2e-machines-grantor@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
grantor_token: jsonpath "$.access_token"
grantor_account_id: jsonpath "$.account.id"

# --- Product ---
POST {{base_url}}/v1/products
Authorization: Bearer {{grantor_token}}
Content-Type: application/json
{ "name": "Grant Widget", "slug": "grant-widget" }
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Grantee signup ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Grantee Machines Co",
  "email": "e2e-machines-grantee@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
grantee_token: jsonpath "$.access_token"
grantee_account_id: jsonpath "$.account.id"

# --- Grantor issues grant to grantee ---
POST {{base_url}}/v1/accounts/{{grantor_account_id}}/grants
Authorization: Bearer {{grantor_token}}
Content-Type: application/json
{
  "grantee_account_id": "{{grantee_account_id}}",
  "product_id": "{{product_id}}",
  "capabilities": ["LICENSE_CREATE", "CUSTOMER_CREATE", "MACHINE_READ"]
}
HTTP 201
[Captures]
grant_id: jsonpath "$.id"

# --- Grantee accepts the grant ---
POST {{base_url}}/v1/grants/{{grant_id}}/accept
Authorization: Bearer {{grantee_token}}
HTTP 200

# --- Grantee creates a license under the grant ---
POST {{base_url}}/v1/grants/{{grant_id}}/licenses
Authorization: Bearer {{grantee_token}}
Content-Type: application/json
{ "customer": { "email": "e2e-machines-grant-buyer@example.com" } }
HTTP 201
[Captures]
grant_license_id: jsonpath "$.license.id"

# --- Grantor activates a machine on the grant-scoped license ---
# (No grant-scoped activate route; license lives in grantor's tenant.)
POST {{base_url}}/v1/licenses/{{grant_license_id}}/activate
Authorization: Bearer {{grantor_token}}
Content-Type: application/json
{ "fingerprint": "fp-grant-alpha", "hostname": "host-grant-alpha" }
HTTP 200

# --- Grantee lists machines via the grant-scoped path — expect 1 machine ---
GET {{base_url}}/v1/grants/{{grant_id}}/licenses/{{grant_license_id}}/machines
Authorization: Bearer {{grantee_token}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].fingerprint" == "fp-grant-alpha"

# --- Grantor creates a SEPARATE license NOT under the grant (direct product path) ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{grantor_token}}
Content-Type: application/json
{ "customer": { "email": "e2e-machines-other-buyer@example.com" } }
HTTP 201
[Captures]
other_license_id: jsonpath "$.license.id"

# --- Grantee tries to list machines on the OTHER license via the grant-scoped path -> 404 ---
# The grantee gate rejects with 404 (not 403) to avoid leaking license existence
# across grant boundaries.
GET {{base_url}}/v1/grants/{{grant_id}}/licenses/{{other_license_id}}/machines
Authorization: Bearer {{grantee_token}}
HTTP 404
[Asserts]
jsonpath "$.error.code" == "license_not_found"
