# =========================================================
# Bulk license creation: POST /v1/products/:id/licenses/bulk
# =========================================================

# --- Setup: signup + product ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Bulk Test Co",
  "email": "e2e-bulk@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
api_key: jsonpath "$.api_key"

POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Bulk Product",
  "slug": "bulk-product"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Bulk create 3 licenses ---
POST {{base_url}}/v1/products/{{product_id}}/licenses/bulk
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "licenses": [
    {"license_type": "perpetual", "licensee_name": "Alice"},
    {"license_type": "timed", "licensee_name": "Bob", "expires_at": "2030-01-01T00:00:00Z"},
    {"license_type": "trial", "licensee_name": "Charlie"}
  ]
}
HTTP 201
[Asserts]
jsonpath "$.results" count == 3
jsonpath "$.results[0].license" exists
jsonpath "$.results[0].license_key" exists
jsonpath "$.results[0].license.status" == "active"
jsonpath "$.results[0].license.licensee_name" == "Alice"
jsonpath "$.results[1].license.license_type" == "timed"
jsonpath "$.results[1].license.licensee_name" == "Bob"
jsonpath "$.results[2].license.license_type" == "trial"
jsonpath "$.results[2].license.licensee_name" == "Charlie"

# --- Verify all 3 appear in list ---
GET {{base_url}}/v1/licenses
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 3
jsonpath "$.has_more" exists

# --- Empty array rejected ---
POST {{base_url}}/v1/products/{{product_id}}/licenses/bulk
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "licenses": []
}
HTTP 422
