# =========================================================
# Domain Events (O2): list, get, filter by resource_type,
# event_type, and resource_id.
# =========================================================

# --- Step 1: signup to get API key ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Events Test Co",
  "email": "e2e-events@test.com",
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
  "name": "Events Product",
  "slug": "events-product"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Step 3: create customer ---
POST {{base_url}}/v1/customers
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "email": "events-cust@example.com",
  "name": "Events Customer"
}
HTTP 201
[Captures]
customer_id: jsonpath "$.id"

# --- Step 4: create license (triggers license.created domain event) ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer_id": "{{customer_id}}"
}
HTTP 201
[Captures]
license_id: jsonpath "$.license.id"

# --- Step 5: list events — should have at least 1 ---
GET {{base_url}}/v1/events
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count >= 1

# --- Step 6: filter by event_type=license.created and capture first event ID ---
GET {{base_url}}/v1/events?event_type=license.created
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count >= 1
jsonpath "$.data[0].event_type" == "license.created"
jsonpath "$.data[0].resource_type" == "license"
[Captures]
event_id: jsonpath "$.data[0].id"

# --- Step 7: get single event by ID ---
GET {{base_url}}/v1/events/{{event_id}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{event_id}}"
jsonpath "$.event_type" == "license.created"
jsonpath "$.resource_type" == "license"

# --- Step 8: filter by resource_type=license ---
GET {{base_url}}/v1/events?resource_type=license
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count >= 1
jsonpath "$.data[0].resource_type" == "license"

# --- Step 9: filter by event_type=license.created ---
GET {{base_url}}/v1/events?event_type=license.created
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count >= 1
jsonpath "$.data[0].event_type" == "license.created"

# --- Step 10: suspend the license (triggers license.suspended event) ---
POST {{base_url}}/v1/licenses/{{license_id}}/suspend
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.status" == "suspended"

# --- Step 11: filter by event_type=license.suspended ---
GET {{base_url}}/v1/events?event_type=license.suspended
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].event_type" == "license.suspended"

# --- Step 12: filter by resource_id — at least 2 events (created + suspended) ---
GET {{base_url}}/v1/events?resource_id={{license_id}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count >= 2
