# --- Setup: signup to get API key ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Products Test Co",
  "email": "e2e-products@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
api_key: jsonpath "$.api_key"

# --- Create product ---
POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "My Product",
  "slug": "my-product"
}
HTTP 201
[Asserts]
jsonpath "$.id" exists
jsonpath "$.name" == "My Product"
jsonpath "$.slug" == "my-product"
[Captures]
product_id: jsonpath "$.id"

# --- Duplicate slug is rejected with 409, not 500 ---
POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Another name, same slug",
  "slug": "my-product"
}
HTTP 409
[Asserts]
jsonpath "$.error.code" == "product_already_exists"
jsonpath "$.error.message" contains "already exists"

# --- List products ---
GET {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" exists
jsonpath "$.pagination" exists
jsonpath "$.data" count >= 1

# --- Get product by ID ---
GET {{base_url}}/v1/products/{{product_id}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{product_id}}"
jsonpath "$.name" == "My Product"

# --- Update product ---
PATCH {{base_url}}/v1/products/{{product_id}}
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "My Updated Product"
}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{product_id}}"
jsonpath "$.name" == "My Updated Product"

# --- Delete product ---
DELETE {{base_url}}/v1/products/{{product_id}}
Authorization: Bearer {{api_key}}
HTTP 204
