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
  "license_type": "perpetual"
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
jsonpath "$.pagination" exists
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
    { "license_type": "perpetual" },
    { "license_type": "perpetual" }
  ]
}
HTTP 201

GET {{base_url}}/v1/products/{{product_id}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.license_counts.active" == 2
jsonpath "$.license_counts.total" == 3

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
