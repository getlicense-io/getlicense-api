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

# --- List API keys (live) — both signup key and new key are live. ---
GET {{base_url}}/v1/api-keys
X-Environment: live
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" exists
jsonpath "$.pagination" exists
jsonpath "$.data" count >= 2

# --- Create a Test-env API key so we have keys in both environments
#     for the scoping assertions below. The `environment` field in
#     the body is authoritative here; X-Environment is not set because
#     api-key authentication pins env to the authenticating key's env
#     (always live in this test). ---
POST {{base_url}}/v1/api-keys
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "environment": "test",
  "label": "e2e-test-key"
}
HTTP 201
[Asserts]
jsonpath "$.api_key.environment" == "test"
[Captures]
test_key_id: jsonpath "$.api_key.id"
test_raw_key: jsonpath "$.raw_key"

# --- List with a TEST api key → only the 1 test key is returned.
#     The list endpoint filters by environment at the SQL level so
#     the dashboard doesn't see cross-env leakage. ---
GET {{base_url}}/v1/api-keys
Authorization: Bearer {{test_raw_key}}
HTTP 200
[Asserts]
jsonpath "$.pagination.total" == 1
jsonpath "$.data[0].id" == "{{test_key_id}}"
jsonpath "$.data[0].environment" == "test"

# --- List with a LIVE api key → only live keys, never the test key. ---
GET {{base_url}}/v1/api-keys
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.pagination.total" >= 2

# --- Delete the new API key ---
DELETE {{base_url}}/v1/api-keys/{{new_key_id}}
Authorization: Bearer {{api_key}}
HTTP 204
