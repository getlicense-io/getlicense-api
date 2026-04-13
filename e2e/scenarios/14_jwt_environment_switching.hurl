# =========================================================
# JWT environment switching: a JWT-authenticated client
# (e.g. the dashboard) can opt into test mode for a request
# via the X-Environment header. Default remains live.
# =========================================================

# --- Setup: signup, then login to get a JWT ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "JWT Env Switch Co",
  "email": "e2e-jwtenv@test.com",
  "password": "password123"
}
HTTP 201

POST {{base_url}}/v1/auth/login
Content-Type: application/json
{
  "email": "e2e-jwtenv@test.com",
  "password": "password123"
}
HTTP 200
[Captures]
jwt: jsonpath "$.access_token"

# --- Create a product (env-agnostic) ---
POST {{base_url}}/v1/products
Authorization: Bearer {{jwt}}
Content-Type: application/json
{
  "name": "JWT Env Product",
  "slug": "jwt-env-product"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Create a license with no header → defaults to live ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{jwt}}
Content-Type: application/json
{
  "license_type": "perpetual",
  "licensee_name": "Live JWT User"
}
HTTP 201
[Asserts]
jsonpath "$.license.environment" == "live"

# --- Create a license with X-Environment: test → goes into test ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{jwt}}
X-Environment: test
Content-Type: application/json
{
  "license_type": "trial",
  "licensee_name": "Test JWT User"
}
HTTP 201
[Asserts]
jsonpath "$.license.environment" == "test"

# --- List licenses with no header → only live ---
GET {{base_url}}/v1/licenses
Authorization: Bearer {{jwt}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].environment" == "live"
jsonpath "$.data[0].licensee_name" == "Live JWT User"

# --- List licenses with X-Environment: live → still only live ---
GET {{base_url}}/v1/licenses
Authorization: Bearer {{jwt}}
X-Environment: live
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].environment" == "live"

# --- List licenses with X-Environment: test → only test ---
GET {{base_url}}/v1/licenses
Authorization: Bearer {{jwt}}
X-Environment: test
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].environment" == "test"
jsonpath "$.data[0].licensee_name" == "Test JWT User"

# --- Custom X-Environment slug is accepted (empty result under RLS) ---
# With user-defined environments the middleware no longer enforces a
# fixed allow-list — any well-formed slug passes. The account here
# has only live/test seeded, so listing licenses under "staging"
# returns an empty set via RLS, not an error.
GET {{base_url}}/v1/licenses
Authorization: Bearer {{jwt}}
X-Environment: staging
HTTP 200
[Asserts]
jsonpath "$.data" count == 0

# --- Malformed X-Environment slug → 422 ---
GET {{base_url}}/v1/licenses
Authorization: Bearer {{jwt}}
X-Environment: Staging!
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# --- Create an API key in test mode via JWT, then verify it works ---
POST {{base_url}}/v1/api-keys
Authorization: Bearer {{jwt}}
X-Environment: test
Content-Type: application/json
{
  "environment": "test",
  "label": "from-jwt-in-test-mode"
}
HTTP 201
[Asserts]
jsonpath "$.api_key.environment" == "test"

# --- API key auth ignores X-Environment — its own env wins ---
# Get a live API key (signup gave us one)
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "API Key Header Co",
  "email": "e2e-apikeyhdr@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
live_api_key: jsonpath "$.api_key"

GET {{base_url}}/v1/licenses
Authorization: Bearer {{live_api_key}}
X-Environment: test
HTTP 200
[Asserts]
# Live API key sees only live licenses — the X-Environment header is ignored.
jsonpath "$.data" count == 0
