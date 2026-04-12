# =========================================================
# Product heartbeat_timeout: create and update products
# with the heartbeat_timeout field.
# =========================================================

# --- Setup: signup ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Heartbeat Test Co",
  "email": "e2e-heartbeat@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
api_key: jsonpath "$.api_key"

# --- Create product without heartbeat_timeout (defaults to null) ---
POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "No Heartbeat Product",
  "slug": "no-heartbeat"
}
HTTP 201
[Asserts]
jsonpath "$.id" exists
jsonpath "$.heartbeat_timeout" not exists
[Captures]
product_id: jsonpath "$.id"

# --- Update product to set heartbeat_timeout ---
PATCH {{base_url}}/v1/products/{{product_id}}
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "heartbeat_timeout": 3600
}
HTTP 200
[Asserts]
jsonpath "$.heartbeat_timeout" == 3600

# --- Get product — heartbeat_timeout persists ---
GET {{base_url}}/v1/products/{{product_id}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.heartbeat_timeout" == 3600

# --- Update other fields — heartbeat_timeout unchanged ---
PATCH {{base_url}}/v1/products/{{product_id}}
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Renamed Heartbeat Product"
}
HTTP 200
[Asserts]
jsonpath "$.name" == "Renamed Heartbeat Product"
jsonpath "$.heartbeat_timeout" == 3600
