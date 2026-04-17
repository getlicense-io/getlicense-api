# =========================================================
# P3: validation_ttl_sec — cascade from policy, override wins,
# bounds rejection, cascade on policy update, default fallback.
# =========================================================

# --- Setup: signup ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "TTL Test Co",
  "email": "e2e-ttl@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
api_key: jsonpath "$.api_key"

# --- Create product (auto-creates default policy) ---
POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "TTL Product",
  "slug": "ttl-product"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Get the auto-created default policy ---
GET {{base_url}}/v1/products/{{product_id}}/policies
Authorization: Bearer {{api_key}}
HTTP 200
[Captures]
policy_id: jsonpath "$.data[0].id"

# --- Update policy: set validation_ttl_sec = 600 ---
PATCH {{base_url}}/v1/policies/{{policy_id}}
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "validation_ttl_sec": 600
}
HTTP 200
[Asserts]
jsonpath "$.validation_ttl_sec" == 600

# --- Reject TTL below minimum ---
PATCH {{base_url}}/v1/policies/{{policy_id}}
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "validation_ttl_sec": 30
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "policy_invalid_ttl"

# --- Reject TTL above maximum ---
PATCH {{base_url}}/v1/policies/{{policy_id}}
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "validation_ttl_sec": 2592001
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "policy_invalid_ttl"

# --- Create license A under the policy (no override) ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer": {"email": "ttl-user@example.com"}
}
HTTP 201
[Captures]
license_key_a: jsonpath "$.license_key"

# --- Validate license A — TTL mirrors policy value (600) ---
POST {{base_url}}/v1/validate
Content-Type: application/json
{
  "license_key": "{{license_key_a}}"
}
HTTP 200
[Asserts]
jsonpath "$.valid" == true
jsonpath "$.validation_ttl_sec" == 600

# --- Create license B with an override of 120 ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer": {"email": "ttl-override@example.com"},
  "overrides": {"validation_ttl_sec": 120}
}
HTTP 201
[Captures]
license_key_b: jsonpath "$.license_key"

# --- Validate license B — override wins (120) ---
POST {{base_url}}/v1/validate
Content-Type: application/json
{
  "license_key": "{{license_key_b}}"
}
HTTP 200
[Asserts]
jsonpath "$.valid" == true
jsonpath "$.validation_ttl_sec" == 120

# --- Reject license-create with bogus override TTL ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer": {"email": "ttl-bogus@example.com"},
  "overrides": {"validation_ttl_sec": 10}
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "policy_invalid_ttl"

# --- Cascade: bump policy TTL to 900, re-validate license A → new TTL ---
PATCH {{base_url}}/v1/policies/{{policy_id}}
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "validation_ttl_sec": 900
}
HTTP 200

POST {{base_url}}/v1/validate
Content-Type: application/json
{
  "license_key": "{{license_key_a}}"
}
HTTP 200
[Asserts]
jsonpath "$.valid" == true
jsonpath "$.validation_ttl_sec" == 900

# --- License B still pinned to its override (120) even after policy change ---
POST {{base_url}}/v1/validate
Content-Type: application/json
{
  "license_key": "{{license_key_b}}"
}
HTTP 200
[Asserts]
jsonpath "$.valid" == true
jsonpath "$.validation_ttl_sec" == 120

# --- Server-default fallback: a second product with an untouched
#     default policy (no validation_ttl_sec set) yields the server
#     default of 3600 on validate. Proves override > policy > default. ---
POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "TTL Product 2",
  "slug": "ttl-product-2"
}
HTTP 201
[Captures]
product_id_2: jsonpath "$.id"

POST {{base_url}}/v1/products/{{product_id_2}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer": {"email": "ttl-default@example.com"}
}
HTTP 201
[Captures]
license_key_c: jsonpath "$.license_key"

POST {{base_url}}/v1/validate
Content-Type: application/json
{
  "license_key": "{{license_key_c}}"
}
HTTP 200
[Asserts]
jsonpath "$.valid" == true
jsonpath "$.validation_ttl_sec" == 3600
