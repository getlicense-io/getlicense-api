# --- Setup: signup to get initial API key ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "APIKeys Test Co",
  "email": "e2e-apikeys@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
api_key: jsonpath "$.api_key"

# --- Create a new API key ---
POST {{base_url}}/v1/api-keys
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "environment": "live"
}
HTTP 201
[Asserts]
jsonpath "$.api_key" exists
jsonpath "$.raw_key" exists
jsonpath "$.api_key.environment" == "live"
[Captures]
new_key_id: jsonpath "$.api_key.id"

# --- List API keys ---
GET {{base_url}}/v1/api-keys
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" exists
jsonpath "$.pagination" exists
jsonpath "$.data" count >= 2

# --- Delete the new API key ---
DELETE {{base_url}}/v1/api-keys/{{new_key_id}}
Authorization: Bearer {{api_key}}
HTTP 204
