# --- Setup: signup to get API key ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Validate Test Co",
  "email": "e2e-validate@test.com",
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
  "name": "Validate Product",
  "slug": "validate-product"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Setup: create license ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "license_type": "perpetual"
}
HTTP 201
[Captures]
license_id: jsonpath "$.license.id"
license_key: jsonpath "$.license_key"

# --- Validate valid license (no auth required) ---
POST {{base_url}}/v1/validate
Content-Type: application/json
{
  "license_key": "{{license_key}}"
}
HTTP 200
[Asserts]
jsonpath "$.valid" == true
jsonpath "$.license" exists
jsonpath "$.license.status" == "active"

# --- Revoke the license ---
DELETE {{base_url}}/v1/licenses/{{license_id}}
Authorization: Bearer {{api_key}}
HTTP 204

# --- Validate revoked license — returns error ---
POST {{base_url}}/v1/validate
Content-Type: application/json
{
  "license_key": "{{license_key}}"
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "license_revoked"
