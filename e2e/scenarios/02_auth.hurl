# --- Signup ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Auth Test Co",
  "email": "e2e-auth@test.com",
  "password": "password123"
}
HTTP 201
[Asserts]
jsonpath "$.account" exists
jsonpath "$.user" exists
jsonpath "$.api_key" exists
jsonpath "$.user.email" == "e2e-auth@test.com"
[Captures]
api_key: jsonpath "$.api_key"

# --- Duplicate email returns 409 ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Auth Test Co Dupe",
  "email": "e2e-auth@test.com",
  "password": "password123"
}
HTTP 409
[Asserts]
jsonpath "$.error.code" == "email_already_exists"

# --- Login ---
POST {{base_url}}/v1/auth/login
Content-Type: application/json
{
  "email": "e2e-auth@test.com",
  "password": "password123"
}
HTTP 200
[Asserts]
jsonpath "$.access_token" exists
jsonpath "$.refresh_token" exists
jsonpath "$.token_type" == "Bearer"
jsonpath "$.expires_in" == 900
[Captures]
access_token: jsonpath "$.access_token"
refresh_token: jsonpath "$.refresh_token"

# --- Wrong password returns 401 ---
POST {{base_url}}/v1/auth/login
Content-Type: application/json
{
  "email": "e2e-auth@test.com",
  "password": "wrongpassword"
}
HTTP 401
[Asserts]
jsonpath "$.error.code" == "authentication_required"

# --- Refresh tokens ---
POST {{base_url}}/v1/auth/refresh
Content-Type: application/json
{
  "refresh_token": "{{refresh_token}}"
}
HTTP 200
[Asserts]
jsonpath "$.access_token" exists
jsonpath "$.refresh_token" exists
jsonpath "$.token_type" == "Bearer"
[Captures]
access_token: jsonpath "$.access_token"
refresh_token: jsonpath "$.refresh_token"

# --- Me (authenticated via JWT) ---
GET {{base_url}}/v1/auth/me
Authorization: Bearer {{access_token}}
HTTP 200
[Asserts]
jsonpath "$.account" exists
jsonpath "$.user" exists
jsonpath "$.user.email" == "e2e-auth@test.com"

# --- Logout ---
POST {{base_url}}/v1/auth/logout
Content-Type: application/json
{
  "refresh_token": "{{refresh_token}}"
}
HTTP 204
