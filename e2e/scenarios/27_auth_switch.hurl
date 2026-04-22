# =========================================================
# POST /v1/auth/switch — reissue a JWT pair scoped to a
# specific membership. Identity auth only. An identity can
# switch into any membership it holds (this scenario uses
# the trivial single-membership case — the shape is the
# same for multi-account identities).
# =========================================================

# --- Step 1: signup → capture JWT + membership_id ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Switch E2E Co",
  "email": "e2e-switch-27@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
access_token: jsonpath "$.access_token"
api_key: jsonpath "$.api_key"
account_id: jsonpath "$.account.id"
membership_id: jsonpath "$.membership.membership_id"

# --- Step 2: switch into the same membership → 200, new
#     access_token + refresh_token, current_account matches. ---
POST {{base_url}}/v1/auth/switch
Authorization: Bearer {{access_token}}
Content-Type: application/json
{
  "membership_id": "{{membership_id}}"
}
HTTP 200
[Asserts]
jsonpath "$.access_token" exists
jsonpath "$.refresh_token" exists
jsonpath "$.token_type" == "Bearer"
jsonpath "$.current_account.id" == "{{account_id}}"
jsonpath "$.memberships[0].membership_id" == "{{membership_id}}"

# --- Step 3: well-formed UUID that is not an active membership for
#     this identity → 403 permission_denied. (Using a non-zero
#     UUID here — the required-validator would short-circuit a
#     zero UUID with 422, which is a different branch.) ---
POST {{base_url}}/v1/auth/switch
Authorization: Bearer {{access_token}}
Content-Type: application/json
{
  "membership_id": "11111111-1111-1111-1111-111111111111"
}
HTTP 403
[Asserts]
jsonpath "$.error.code" == "permission_denied"

# --- Step 4: API-key auth is rejected — switch requires identity
#     (JWT) auth. The handler returns 401 authentication_required. ---
POST {{base_url}}/v1/auth/switch
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "membership_id": "{{membership_id}}"
}
HTTP 401
[Asserts]
jsonpath "$.error.code" == "authentication_required"

# --- Step 5: malformed JSON body (wrong type for membership_id) →
#     422 validation_error. errorHandler maps json.UnmarshalTypeError
#     to this typed code. L6: same status as validator-level failures
#     so clients don't see 400 vs 422 drift on functionally identical
#     "bad request body" errors. ---
POST {{base_url}}/v1/auth/switch
Authorization: Bearer {{access_token}}
Content-Type: application/json
{
  "membership_id": 42
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"
