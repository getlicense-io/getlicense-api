# JWT revocation: per-token (jti) via /auth/logout and bulk via
# /auth/logout-all. After this PR every signed JWT carries a kid header
# and a jti claim; the verifier rejects tokens missing either, and the
# middleware checks revoked_jtis + identity_session_invalidations on
# every JWT auth request.

# --- Signup creates a fresh identity with one access + refresh token ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Revocation Test Co",
  "email": "e2e-revocation@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
access_token: jsonpath "$.access_token"
refresh_token: jsonpath "$.refresh_token"

# --- /auth/me with the fresh access token works ---
GET {{base_url}}/v1/auth/me
Authorization: Bearer {{access_token}}
HTTP 200

# --- Logout revokes the access token (per-jti) AND deletes the
#     refresh token. Requires identity auth (the handler reads jti +
#     expiry from the auth context). ---
POST {{base_url}}/v1/auth/logout
Authorization: Bearer {{access_token}}
Content-Type: application/json
{
  "refresh_token": "{{refresh_token}}"
}
HTTP 204

# --- The same access token now fails: jti is in revoked_jtis. ---
GET {{base_url}}/v1/auth/me
Authorization: Bearer {{access_token}}
HTTP 401
[Asserts]
jsonpath "$.error.code" == "authentication_required"

# --- The refresh token is also gone — refresh fails. ---
POST {{base_url}}/v1/auth/refresh
Content-Type: application/json
{
  "refresh_token": "{{refresh_token}}"
}
HTTP 401

# --- Login again to mint a brand-new pair. ---
POST {{base_url}}/v1/auth/login
Content-Type: application/json
{
  "email": "e2e-revocation@test.com",
  "password": "password123"
}
HTTP 200
[Captures]
session_a_access: jsonpath "$.access_token"
session_a_refresh: jsonpath "$.refresh_token"

# --- Open a SECOND concurrent session for the same identity. ---
POST {{base_url}}/v1/auth/login
Content-Type: application/json
{
  "email": "e2e-revocation@test.com",
  "password": "password123"
}
HTTP 200
[Captures]
session_b_access: jsonpath "$.access_token"
session_b_refresh: jsonpath "$.refresh_token"

# --- Both sessions are valid right now. ---
GET {{base_url}}/v1/auth/me
Authorization: Bearer {{session_a_access}}
HTTP 200

GET {{base_url}}/v1/auth/me
Authorization: Bearer {{session_b_access}}
HTTP 200

# --- /auth/logout-all sets the per-identity session-invalidation
#     cutoff to NOW and deletes every refresh token. ---
POST {{base_url}}/v1/auth/logout-all
Authorization: Bearer {{session_a_access}}
HTTP 204

# --- Both access tokens were issued before the cutoff: both fail. ---
GET {{base_url}}/v1/auth/me
Authorization: Bearer {{session_a_access}}
HTTP 401

GET {{base_url}}/v1/auth/me
Authorization: Bearer {{session_b_access}}
HTTP 401

# --- Both refresh tokens were deleted: both fail. ---
POST {{base_url}}/v1/auth/refresh
Content-Type: application/json
{
  "refresh_token": "{{session_a_refresh}}"
}
HTTP 401

POST {{base_url}}/v1/auth/refresh
Content-Type: application/json
{
  "refresh_token": "{{session_b_refresh}}"
}
HTTP 401

# --- A fresh login AFTER the cutoff still works (the cutoff only
#     applies to tokens issued before it). ---
POST {{base_url}}/v1/auth/login
Content-Type: application/json
{
  "email": "e2e-revocation@test.com",
  "password": "password123"
}
HTTP 200
[Captures]
session_c_access: jsonpath "$.access_token"

GET {{base_url}}/v1/auth/me
Authorization: Bearer {{session_c_access}}
HTTP 200
