# =========================================================
# Environment isolation: test/live API keys see only their
# own licenses, machines, and webhook endpoints.
# =========================================================

# --- Setup: signup (gets a live API key) ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Env Isolation Co",
  "email": "e2e-enviso@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
live_key: jsonpath "$.api_key"

# --- Create a test API key ---
POST {{base_url}}/v1/api-keys
Authorization: Bearer {{live_key}}
Content-Type: application/json
{
  "environment": "test"
}
HTTP 201
[Asserts]
jsonpath "$.api_key.environment" == "test"
jsonpath "$.raw_key" startsWith "gl_test_"
[Captures]
test_key: jsonpath "$.raw_key"

# --- Create product (shared across environments) ---
POST {{base_url}}/v1/products
Authorization: Bearer {{live_key}}
Content-Type: application/json
{
  "name": "Env Iso Product",
  "slug": "env-iso-product"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Create license with LIVE key ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{live_key}}
Content-Type: application/json
{
  "license_type": "perpetual",
  "licensee_name": "Live User"
}
HTTP 201
[Asserts]
jsonpath "$.license.environment" == "live"
[Captures]
live_license_id: jsonpath "$.license.id"

# --- Create license with TEST key ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{test_key}}
Content-Type: application/json
{
  "license_type": "trial",
  "licensee_name": "Test User"
}
HTTP 201
[Asserts]
jsonpath "$.license.environment" == "test"
[Captures]
test_license_id: jsonpath "$.license.id"

# --- List licenses with LIVE key — should only see live license ---
GET {{base_url}}/v1/licenses
Authorization: Bearer {{live_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].licensee_name" == "Live User"
jsonpath "$.data[0].environment" == "live"
jsonpath "$.pagination.total" == 1

# --- List licenses with TEST key — should only see test license ---
GET {{base_url}}/v1/licenses
Authorization: Bearer {{test_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].licensee_name" == "Test User"
jsonpath "$.data[0].environment" == "test"
jsonpath "$.pagination.total" == 1

# --- Get live license with test key — should 404 (RLS hides it) ---
GET {{base_url}}/v1/licenses/{{live_license_id}}
Authorization: Bearer {{test_key}}
HTTP 404

# --- Activate machine with TEST key ---
POST {{base_url}}/v1/licenses/{{test_license_id}}/activate
Authorization: Bearer {{test_key}}
Content-Type: application/json
{
  "fingerprint": "test-machine-001"
}
HTTP 201
[Asserts]
jsonpath "$.environment" == "test"

# --- Create webhook endpoint with TEST key ---
POST {{base_url}}/v1/webhooks
Authorization: Bearer {{test_key}}
Content-Type: application/json
{
  "url": "https://example.com/test-hook"
}
HTTP 201
[Asserts]
jsonpath "$.environment" == "test"
[Captures]
test_webhook_id: jsonpath "$.id"

# --- List webhooks with LIVE key — should not see test webhook ---
GET {{base_url}}/v1/webhooks
Authorization: Bearer {{live_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 0
jsonpath "$.pagination.total" == 0

# --- List webhooks with TEST key — should see test webhook ---
GET {{base_url}}/v1/webhooks
Authorization: Bearer {{test_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].environment" == "test"
