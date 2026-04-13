# =========================================================
# Environments: per-account data partitions (live, test,
# plus up to one user-defined). Dashboard drives this via
# JWT; no API-key path is required.
# =========================================================

# --- Setup: signup, then login to get a JWT ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Envs Co",
  "email": "e2e-envs@test.com",
  "password": "password123"
}
HTTP 201

POST {{base_url}}/v1/auth/login
Content-Type: application/json
{
  "email": "e2e-envs@test.com",
  "password": "password123"
}
HTTP 200
[Captures]
jwt: jsonpath "$.access_token"

# --- A fresh account has the two default environments seeded ---
GET {{base_url}}/v1/environments
Authorization: Bearer {{jwt}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 2
jsonpath "$.data[0].slug" == "live"
jsonpath "$.data[0].name" == "Live"
jsonpath "$.data[0].color" == "emerald"
jsonpath "$.data[1].slug" == "test"
jsonpath "$.data[1].name" == "Test"
jsonpath "$.data[1].color" == "amber"

# --- Duplicate of a seeded slug is 409 (count=2, below the cap) ---
POST {{base_url}}/v1/environments
Authorization: Bearer {{jwt}}
Content-Type: application/json
{
  "slug": "live",
  "name": "Live 2"
}
HTTP 409
[Asserts]
jsonpath "$.error.code" == "environment_already_exists"

# --- Create a user-defined environment ---
POST {{base_url}}/v1/environments
Authorization: Bearer {{jwt}}
Content-Type: application/json
{
  "slug": "staging",
  "name": "Staging",
  "description": "Pre-release",
  "icon": "beaker",
  "color": "violet"
}
HTTP 201
[Captures]
staging_id: jsonpath "$.id"
[Asserts]
jsonpath "$.slug" == "staging"
jsonpath "$.name" == "Staging"
jsonpath "$.icon" == "beaker"
jsonpath "$.color" == "violet"
jsonpath "$.position" == 2

# --- List now returns three environments ---
GET {{base_url}}/v1/environments
Authorization: Bearer {{jwt}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 3
jsonpath "$.data[2].slug" == "staging"

# --- At the cap: any 4th env (even a unique slug) trips the limit ---
POST {{base_url}}/v1/environments
Authorization: Bearer {{jwt}}
Content-Type: application/json
{
  "slug": "preview",
  "name": "Preview"
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "environment_limit_reached"

# --- Malformed slug is a 422 ---
POST {{base_url}}/v1/environments
Authorization: Bearer {{jwt}}
Content-Type: application/json
{
  "slug": "Bad Slug!",
  "name": "Bad"
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# --- Overlong name (>32 chars) is a 422 ---
# The dashboard enforces maxLength client-side; the backend check is
# defense-in-depth for curl / script clients that bypass the form.
POST {{base_url}}/v1/environments
Authorization: Bearer {{jwt}}
Content-Type: application/json
{
  "slug": "longname",
  "name": "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn"
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# --- The new slug works as an X-Environment header for licenses ---
POST {{base_url}}/v1/products
Authorization: Bearer {{jwt}}
Content-Type: application/json
{
  "name": "Env Product",
  "slug": "env-product"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{jwt}}
X-Environment: staging
Content-Type: application/json
{
  "license_type": "perpetual",
  "licensee_name": "Staging User"
}
HTTP 201
[Captures]
staging_license_id: jsonpath "$.license.id"

# --- Deleting an environment with active licenses is blocked ---
DELETE {{base_url}}/v1/environments/{{staging_id}}
Authorization: Bearer {{jwt}}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "environment_not_empty"

# --- Revoke the staging license, then deletion succeeds ---
DELETE {{base_url}}/v1/licenses/{{staging_license_id}}
Authorization: Bearer {{jwt}}
X-Environment: staging
HTTP 204

DELETE {{base_url}}/v1/environments/{{staging_id}}
Authorization: Bearer {{jwt}}
HTTP 204

# --- Back to two envs ---
GET {{base_url}}/v1/environments
Authorization: Bearer {{jwt}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 2

# --- Cannot delete the last environment ---
# Get live's id
GET {{base_url}}/v1/environments
Authorization: Bearer {{jwt}}
HTTP 200
[Captures]
live_id: jsonpath "$.data[0].id"
test_id: jsonpath "$.data[1].id"

# Delete test first (empty → allowed)
DELETE {{base_url}}/v1/environments/{{test_id}}
Authorization: Bearer {{jwt}}
HTTP 204

# Deleting the remaining live env is forbidden
DELETE {{base_url}}/v1/environments/{{live_id}}
Authorization: Bearer {{jwt}}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "last_environment"
