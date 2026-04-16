# =========================================================
# Global Search (O5): search across licenses, customers,
# products, and machines via GET /v1/search?q=<query>.
# =========================================================

# --- Step 1: signup to get API key ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Search Test Co",
  "email": "e2e-search@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
api_key: jsonpath "$.api_key"

# --- Step 2: create product ---
POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Search Widget",
  "slug": "search-widget"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Step 3: create customer ---
POST {{base_url}}/v1/customers
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "email": "search-cust@example.com",
  "name": "Search Customer"
}
HTTP 201
[Captures]
customer_id: jsonpath "$.id"

# --- Step 4: create license ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer_id": "{{customer_id}}"
}
HTTP 201
[Captures]
license_id: jsonpath "$.license.id"
key_prefix: jsonpath "$.license.key_prefix"

# --- Step 5: activate a machine ---
POST {{base_url}}/v1/licenses/{{license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "search-fp-001",
  "hostname": "search-host-alpha"
}
HTTP 200

# --- Step 6: search requires q parameter ---
GET {{base_url}}/v1/search
Authorization: Bearer {{api_key}}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# --- Step 7: search by license key prefix ---
GET {{base_url}}/v1/search?q=type:license key:{{key_prefix}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.licenses" count >= 1
jsonpath "$.licenses[0].id" == "{{license_id}}"

# --- Step 8: search by customer email ---
GET {{base_url}}/v1/search?q=type:customer email:search-cust@
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.customers" count >= 1
jsonpath "$.customers[0].email" == "search-cust@example.com"

# --- Step 9: search by product slug ---
GET {{base_url}}/v1/search?q=type:product slug:search-widget
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.products" count >= 1
jsonpath "$.products[0].slug" == "search-widget"

# --- Step 10: search by machine fingerprint ---
GET {{base_url}}/v1/search?q=type:machine fingerprint:search-fp
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.machines" count >= 1
jsonpath "$.machines[0].fingerprint" == "search-fp-001"

# --- Step 11: bare word search (all types) ---
GET {{base_url}}/v1/search?q=search
Authorization: Bearer {{api_key}}
HTTP 200

# --- Step 12: types query param filter ---
GET {{base_url}}/v1/search?q=search&types=product,customer
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.products" count >= 1
jsonpath "$.customers" count >= 1

# --- Step 13: unknown type in DSL ---
GET {{base_url}}/v1/search?q=type:foobar test
Authorization: Bearer {{api_key}}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# --- Step 14: unknown type in types param ---
GET {{base_url}}/v1/search?q=test&types=badtype
Authorization: Bearer {{api_key}}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# --- Step 15: no results returns 200 with empty ---
GET {{base_url}}/v1/search?q=type:customer email:nonexistent-xyzzy-9999@
Authorization: Bearer {{api_key}}
HTTP 200

# --- Step 16: unauthenticated search ---
GET {{base_url}}/v1/search?q=test
HTTP 401
