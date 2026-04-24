# --- Setup: signup to get API key ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Licenses Test Co",
  "email": "e2e-licenses@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
api_key: jsonpath "$.api_key"

# --- Setup: create product ---
POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "License Product",
  "slug": "license-product"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Create license ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer": {"email": "license-one@example.com"}
}
HTTP 201
[Asserts]
jsonpath "$.license" exists
jsonpath "$.license_key" exists
jsonpath "$.license.status" == "active"
[Captures]
license_id: jsonpath "$.license.id"
license_key: jsonpath "$.license_key"

# --- List licenses ---
GET {{base_url}}/v1/licenses
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" exists
jsonpath "$.has_more" exists
jsonpath "$.data" count >= 1

# --- Get license by ID ---
GET {{base_url}}/v1/licenses/{{license_id}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{license_id}}"
jsonpath "$.status" == "active"

# --- Suspend license ---
POST {{base_url}}/v1/licenses/{{license_id}}/suspend
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{license_id}}"
jsonpath "$.status" == "suspended"

# --- Reinstate license ---
POST {{base_url}}/v1/licenses/{{license_id}}/reinstate
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{license_id}}"
jsonpath "$.status" == "active"

# --- Revoke license ---
DELETE {{base_url}}/v1/licenses/{{license_id}}
Authorization: Bearer {{api_key}}
HTTP 204

# --- GET product surfaces a license_counts summary so the dashboard
#     never has to page through licenses to compute blocking counts. ---
GET {{base_url}}/v1/products/{{product_id}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{product_id}}"
jsonpath "$.license_counts" exists
jsonpath "$.license_counts.total" == 1
jsonpath "$.license_counts.revoked" == 1
jsonpath "$.license_counts.active" == 0
jsonpath "$.license_counts.suspended" == 0

# --- Bulk-revoke covers an active product. Seed two fresh licenses,
#     then DELETE the licenses collection under the product. ---
POST {{base_url}}/v1/products/{{product_id}}/licenses/bulk
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "licenses": [
    {"customer": {"email": "bulk-a@example.com"}},
    {"customer": {"email": "bulk-b@example.com"}}
  ]
}
HTTP 201

GET {{base_url}}/v1/products/{{product_id}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.license_counts.active" == 2
jsonpath "$.license_counts.total" == 3

# --- Product-scoped paginated license listing. The dashboard's product
#     detail page calls this so it never has to fetch the global list
#     and filter client-side (which silently capped at the page size). ---
GET {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" exists
jsonpath "$.has_more" exists
jsonpath "$.data" count == 3

# --- Global license pagination uses the same cursor contract as
#     product-scoped listing. This catches regressions where filters
#     work but cursor boundaries or next_cursor handling drift. ---
GET {{base_url}}/v1/licenses?limit=2
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 2
jsonpath "$.has_more" == true
jsonpath "$.next_cursor" exists
[Captures]
licenses_next_cursor: jsonpath "$.next_cursor"

GET {{base_url}}/v1/licenses?limit=2&cursor={{licenses_next_cursor}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.has_more" == false

DELETE {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.revoked" == 2

GET {{base_url}}/v1/products/{{product_id}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.license_counts.active" == 0
jsonpath "$.license_counts.revoked" == 3
jsonpath "$.license_counts.total" == 3

# --- Seed a tagged license so we can exercise ?status= and ?q= filters.
#     The `?type=` filter that existed in L0 was removed alongside the
#     license_type column; type-shaped narrowing now goes through policies. ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer": {
    "email": "ops@acme.example",
    "name": "Acme Corp"
  }
}
HTTP 201
[Captures]
acme_license_id: jsonpath "$.license.id"

# Status filter: only the Acme license is active; three earlier licenses are revoked.
GET {{base_url}}/v1/licenses?status=active
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].id" == "{{acme_license_id}}"
jsonpath "$.data[0].status" == "active"

GET {{base_url}}/v1/licenses?status=revoked
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 3

# `q` matches the attached customer's name (case-insensitive, substring).
GET {{base_url}}/v1/licenses?q=acme
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].id" == "{{acme_license_id}}"

# `q` matches the attached customer's email domain (substring).
GET {{base_url}}/v1/licenses?q=acme.example
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1

# Invalid status → 422, not silently ignored.
GET {{base_url}}/v1/licenses?status=gibberish
Authorization: Bearer {{api_key}}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"
jsonpath "$.error.message" contains "status"

# Same filters work on the product-scoped list endpoint.
GET {{base_url}}/v1/products/{{product_id}}/licenses?status=active
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].id" == "{{acme_license_id}}"

GET {{base_url}}/v1/products/{{product_id}}/licenses?q=acme
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
