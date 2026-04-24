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
jsonpath "$.has_more" exists
jsonpath "$.data" count >= 1

# --- Product list pagination ---
POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Paged Product A",
  "slug": "paged-product-a"
}
HTTP 201

POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Paged Product B",
  "slug": "paged-product-b"
}
HTTP 201

GET {{base_url}}/v1/products?limit=2
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 2
jsonpath "$.has_more" == true
jsonpath "$.next_cursor" exists
[Captures]
products_next_cursor: jsonpath "$.next_cursor"

GET {{base_url}}/v1/products?limit=2&cursor={{products_next_cursor}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.has_more" == false

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
