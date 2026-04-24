# 33_product_scoped_keys.hurl — exercises the full product-scoped API
# key enforcement matrix. Covers validation errors (Task 11), service-
# level path gate (Task 12), policy/product service gates (Task 13),
# route-level rejection (Task 14), and auto-scope on list endpoints
# (Task 15).

# --- Vendor signup ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "PS Keys Vendor",
  "email": "e2e-pskeys-vendor@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
owner_token: jsonpath "$.access_token"

# --- Two products ---
POST {{base_url}}/v1/products
Authorization: Bearer {{owner_token}}
Content-Type: application/json
{ "name": "Prod A", "slug": "ps-prod-a" }
HTTP 201
[Captures]
product_a: jsonpath "$.id"

POST {{base_url}}/v1/products
Authorization: Bearer {{owner_token}}
Content-Type: application/json
{ "name": "Prod B", "slug": "ps-prod-b" }
HTTP 201
[Captures]
product_b: jsonpath "$.id"

# --- One license per product ---
POST {{base_url}}/v1/products/{{product_a}}/licenses
Authorization: Bearer {{owner_token}}
Content-Type: application/json
{ "customer": { "email": "e2e-pskeys-buyer-a@test.com" } }
HTTP 201
[Captures]
license_a: jsonpath "$.license.id"

POST {{base_url}}/v1/products/{{product_b}}/licenses
Authorization: Bearer {{owner_token}}
Content-Type: application/json
{ "customer": { "email": "e2e-pskeys-buyer-b@test.com" } }
HTTP 201
[Captures]
license_b: jsonpath "$.license.id"

# ---------- Validation errors on key creation (Task 11) ----------

# scope=product without product_id → 422
POST {{base_url}}/v1/api-keys
Authorization: Bearer {{owner_token}}
Content-Type: application/json
{ "environment": "live", "scope": "product" }
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# scope=account_wide WITH product_id → 422
POST {{base_url}}/v1/api-keys
Authorization: Bearer {{owner_token}}
Content-Type: application/json
{ "environment": "live", "scope": "account_wide", "product_id": "{{product_a}}" }
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# unknown scope → 422
POST {{base_url}}/v1/api-keys
Authorization: Bearer {{owner_token}}
Content-Type: application/json
{ "environment": "live", "scope": "garbage" }
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# unknown product_id → 404 (existence-leak avoidance)
POST {{base_url}}/v1/api-keys
Authorization: Bearer {{owner_token}}
Content-Type: application/json
{ "environment": "live", "scope": "product", "product_id": "00000000-0000-0000-0000-000000000000" }
HTTP 404
[Asserts]
jsonpath "$.error.code" == "product_not_found"

# ---------- Successful creation of a product-scoped key ----------

POST {{base_url}}/v1/api-keys
Authorization: Bearer {{owner_token}}
Content-Type: application/json
{ "environment": "live", "scope": "product", "product_id": "{{product_a}}", "label": "PS Keys Product A" }
HTTP 201
[Asserts]
jsonpath "$.api_key.scope" == "product"
jsonpath "$.api_key.product_id" == "{{product_a}}"
jsonpath "$.raw_key" exists
[Captures]
key_a_raw: jsonpath "$.raw_key"

# ---------- Path-bound enforcement (Task 12) ----------

# Key scoped to A accessing license in B → 403
GET {{base_url}}/v1/licenses/{{license_b}}
Authorization: Bearer {{key_a_raw}}
HTTP 403
[Asserts]
jsonpath "$.error.code" == "api_key_scope_mismatch"

# Key scoped to A accessing license in A → 200
GET {{base_url}}/v1/licenses/{{license_a}}
Authorization: Bearer {{key_a_raw}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{license_a}}"

# ---------- Product service gate (Task 13) ----------

# Key scoped to A accessing product A → 200
GET {{base_url}}/v1/products/{{product_a}}
Authorization: Bearer {{key_a_raw}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{product_a}}"

# Key scoped to A accessing product B → 403
GET {{base_url}}/v1/products/{{product_b}}
Authorization: Bearer {{key_a_raw}}
HTTP 403
[Asserts]
jsonpath "$.error.code" == "api_key_scope_mismatch"

# ---------- Auto-scope on list endpoints (Task 15) ----------

# GET /v1/licenses (no filter) → only product A's license
GET {{base_url}}/v1/licenses
Authorization: Bearer {{key_a_raw}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].id" == "{{license_a}}"

# GET /v1/licenses?product_id=<A> → same result (explicit filter matches auth)
GET {{base_url}}/v1/licenses?product_id={{product_a}}
Authorization: Bearer {{key_a_raw}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].id" == "{{license_a}}"

# GET /v1/licenses?product_id=<B> → 403 (conflicting filter)
GET {{base_url}}/v1/licenses?product_id={{product_b}}
Authorization: Bearer {{key_a_raw}}
HTTP 403
[Asserts]
jsonpath "$.error.code" == "api_key_scope_mismatch"

# ---------- Route-level rejection (Task 14) ----------

# /v1/api-keys → 403
GET {{base_url}}/v1/api-keys
Authorization: Bearer {{key_a_raw}}
HTTP 403
[Asserts]
jsonpath "$.error.code" == "api_key_scope_mismatch"

# /v1/products (list) → 403
GET {{base_url}}/v1/products
Authorization: Bearer {{key_a_raw}}
HTTP 403
[Asserts]
jsonpath "$.error.code" == "api_key_scope_mismatch"

# /v1/metrics → 403
GET {{base_url}}/v1/metrics
Authorization: Bearer {{key_a_raw}}
HTTP 403
[Asserts]
jsonpath "$.error.code" == "api_key_scope_mismatch"

# /v1/customers → 403
GET {{base_url}}/v1/customers
Authorization: Bearer {{key_a_raw}}
HTTP 403
[Asserts]
jsonpath "$.error.code" == "api_key_scope_mismatch"
