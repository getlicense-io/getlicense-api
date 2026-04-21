# =========================================================
# Entitlements (L3): registry CRUD, policy/license attach &
# detach, effective set resolution, lease token population,
# validate response, and code format validation.
# =========================================================

# --- Step 1: signup to get API key ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Entitlements Test Co",
  "email": "e2e-entitlements@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
api_key: jsonpath "$.api_key"

# --- Step 2: create a product ---
POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Entitlements Product",
  "slug": "entitlements-product"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Step 3: create two entitlements ---
POST {{base_url}}/v1/entitlements
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "code": "OFFLINE_SUPPORT",
  "name": "Offline Support"
}
HTTP 201
[Asserts]
jsonpath "$.code" == "OFFLINE_SUPPORT"
jsonpath "$.name" == "Offline Support"
[Captures]
offline_id: jsonpath "$.id"

POST {{base_url}}/v1/entitlements
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "code": "PRIORITY_MAIL",
  "name": "Priority Mail Support"
}
HTTP 201
[Asserts]
jsonpath "$.code" == "PRIORITY_MAIL"
[Captures]
priority_id: jsonpath "$.id"

# --- Step 4: list entitlements → both present ---
GET {{base_url}}/v1/entitlements
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 2

# --- Step 5: get default policy id, attach OFFLINE_SUPPORT to it ---
GET {{base_url}}/v1/products/{{product_id}}/policies
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].is_default" == true
[Captures]
policy_id: jsonpath "$.data[0].id"

POST {{base_url}}/v1/policies/{{policy_id}}/entitlements
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "codes": ["OFFLINE_SUPPORT"]
}
HTTP 204

# --- Step 6: list policy entitlements → bare array with one code ---
GET {{base_url}}/v1/policies/{{policy_id}}/entitlements
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$" count == 1
jsonpath "$[0]" == "OFFLINE_SUPPORT"

# --- Step 7: create a license with inline customer ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer": {"email": "ent-holder@example.com", "name": "Ent Holder"}
}
HTTP 201
[Captures]
license_id: jsonpath "$.license.id"
license_key: jsonpath "$.license_key"

# --- Step 8: license entitlements three-set → policy=[OFFLINE_SUPPORT],
#     license=[], effective=[OFFLINE_SUPPORT] ---
GET {{base_url}}/v1/licenses/{{license_id}}/entitlements
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.policy" count == 1
jsonpath "$.policy[0]" == "OFFLINE_SUPPORT"
jsonpath "$.license" count == 0
jsonpath "$.effective" count == 1
jsonpath "$.effective[0]" == "OFFLINE_SUPPORT"

# --- Step 9: attach PRIORITY_MAIL to the license ---
POST {{base_url}}/v1/licenses/{{license_id}}/entitlements
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "codes": ["PRIORITY_MAIL"]
}
HTTP 204

# --- Step 10: effective = [OFFLINE_SUPPORT, PRIORITY_MAIL] (sorted) ---
GET {{base_url}}/v1/licenses/{{license_id}}/entitlements
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.policy" count == 1
jsonpath "$.policy[0]" == "OFFLINE_SUPPORT"
jsonpath "$.license" count == 1
jsonpath "$.license[0]" == "PRIORITY_MAIL"
jsonpath "$.effective" count == 2
jsonpath "$.effective[0]" == "OFFLINE_SUPPORT"
jsonpath "$.effective[1]" == "PRIORITY_MAIL"

# --- Step 11: activate machine → lease_claims.ent contains both codes ---
POST {{base_url}}/v1/licenses/{{license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "ent-fp-1"
}
HTTP 201
[Asserts]
jsonpath "$.lease_token" matches "^gl2\\."
jsonpath "$.lease_claims.ent" count == 2
jsonpath "$.lease_claims.ent[0]" == "OFFLINE_SUPPORT"
jsonpath "$.lease_claims.ent[1]" == "PRIORITY_MAIL"

# --- Step 12: PUT license entitlements to empty → removes license-level ---
PUT {{base_url}}/v1/licenses/{{license_id}}/entitlements
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "codes": []
}
HTTP 204

# --- Step 13: effective reverts to policy only → [OFFLINE_SUPPORT] ---
GET {{base_url}}/v1/licenses/{{license_id}}/entitlements
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.policy" count == 1
jsonpath "$.policy[0]" == "OFFLINE_SUPPORT"
jsonpath "$.license" count == 0
jsonpath "$.effective" count == 1
jsonpath "$.effective[0]" == "OFFLINE_SUPPORT"

# --- Step 14: try DELETE OFFLINE_SUPPORT entitlement → 409 (in use) ---
DELETE {{base_url}}/v1/entitlements/{{offline_id}}
Authorization: Bearer {{api_key}}
HTTP 409
[Asserts]
jsonpath "$.error.code" == "entitlement_in_use"

# --- Step 15: detach from policy first ---
DELETE {{base_url}}/v1/policies/{{policy_id}}/entitlements/OFFLINE_SUPPORT
Authorization: Bearer {{api_key}}
HTTP 204

# --- Step 16: now DELETE OFFLINE_SUPPORT succeeds ---
DELETE {{base_url}}/v1/entitlements/{{offline_id}}
Authorization: Bearer {{api_key}}
HTTP 204

# --- Step 17: validate → entitlements is empty (both gone from license) ---
POST {{base_url}}/v1/validate
Content-Type: application/json
{
  "license_key": "{{license_key}}"
}
HTTP 200
[Asserts]
jsonpath "$.valid" == true
jsonpath "$.entitlements" count == 0

# --- Step 18: invalid code format → 422 ---
POST {{base_url}}/v1/entitlements
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "code": "lowercase",
  "name": "Bad"
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "entitlement_invalid_code"
