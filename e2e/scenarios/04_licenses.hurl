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
