# =========================================================
# Webhook Deliveries (O3): list, get, redeliver.
# The background poller delivers domain_events to webhook
# endpoints every 60s. We use retry to wait for delivery.
# =========================================================

# --- Step 1: signup to get API key ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Delivery Test Co",
  "email": "e2e-deliveries@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
api_key: jsonpath "$.api_key"

# --- Step 2: create webhook endpoint (subscribes to license.created) ---
POST {{base_url}}/v1/webhooks
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "url": "https://example.com/webhook-delivery-test",
  "events": ["license.created"]
}
HTTP 201
[Captures]
webhook_id: jsonpath "$.id"

# --- Step 3: create product ---
POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Delivery Product",
  "slug": "delivery-product"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Step 4: create customer ---
POST {{base_url}}/v1/customers
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "email": "delivery-cust@example.com",
  "name": "Delivery Customer"
}
HTTP 201
[Captures]
customer_id: jsonpath "$.id"

# --- Step 5: create license (triggers domain event + webhook delivery) ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer_id": "{{customer_id}}"
}
HTTP 201

# --- Step 6: list deliveries — retry until the background poller fires ---
GET {{base_url}}/v1/webhooks/{{webhook_id}}/deliveries
Authorization: Bearer {{api_key}}
[Options]
retry: 30
retry-interval: 3000
HTTP 200
[Asserts]
jsonpath "$.data" count >= 1
jsonpath "$.data[0].endpoint_id" == "{{webhook_id}}"
jsonpath "$.data[0].event_type" == "license.created"
jsonpath "$.data[0].domain_event_id" exists
jsonpath "$.data[0].status" exists
jsonpath "$.data[0].response_body_truncated" exists
[Captures]
delivery_id: jsonpath "$.data[0].id"

# --- Step 7: get single delivery ---
GET {{base_url}}/v1/webhooks/{{webhook_id}}/deliveries/{{delivery_id}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{delivery_id}}"
jsonpath "$.endpoint_id" == "{{webhook_id}}"
jsonpath "$.event_type" == "license.created"
jsonpath "$.domain_event_id" exists

# --- Step 8: redeliver ---
POST {{base_url}}/v1/webhooks/{{webhook_id}}/deliveries/{{delivery_id}}/redeliver
Authorization: Bearer {{api_key}}
HTTP 201
[Asserts]
jsonpath "$.id" exists
jsonpath "$.endpoint_id" == "{{webhook_id}}"
jsonpath "$.event_type" == "license.created"
jsonpath "$.domain_event_id" exists
[Captures]
redeliver_id: jsonpath "$.id"

# --- Step 9: verify new delivery exists in list ---
GET {{base_url}}/v1/webhooks/{{webhook_id}}/deliveries
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count >= 2

# --- Step 10: list with event_type filter ---
GET {{base_url}}/v1/webhooks/{{webhook_id}}/deliveries?event_type=license.created
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count >= 2
jsonpath "$.data[0].event_type" == "license.created"

# --- Step 11: list with status filter (check that filter works, may return 0 or more) ---
GET {{base_url}}/v1/webhooks/{{webhook_id}}/deliveries?status=failed
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" exists

# --- Step 12: get delivery not found ---
GET {{base_url}}/v1/webhooks/{{webhook_id}}/deliveries/00000000-0000-0000-0000-000000000000
Authorization: Bearer {{api_key}}
HTTP 404

# --- Step 13: redeliver not found ---
POST {{base_url}}/v1/webhooks/{{webhook_id}}/deliveries/00000000-0000-0000-0000-000000000000/redeliver
Authorization: Bearer {{api_key}}
HTTP 404

# --- Step 14: endpoint not found ---
GET {{base_url}}/v1/webhooks/00000000-0000-0000-0000-000000000000/deliveries
Authorization: Bearer {{api_key}}
HTTP 404
