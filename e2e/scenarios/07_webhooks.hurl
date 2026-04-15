# --- Setup: signup to get API key ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Webhooks Test Co",
  "email": "e2e-webhooks@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
api_key: jsonpath "$.api_key"

# --- Create webhook endpoint ---
POST {{base_url}}/v1/webhooks
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "url": "https://example.com/webhook",
  "events": ["license.created", "license.activated"]
}
HTTP 201
[Asserts]
jsonpath "$.id" exists
jsonpath "$.url" == "https://example.com/webhook"
[Captures]
webhook_id: jsonpath "$.id"

# --- List webhook endpoints ---
GET {{base_url}}/v1/webhooks
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" exists
jsonpath "$.has_more" exists
jsonpath "$.data" count >= 1

# --- Delete webhook endpoint ---
DELETE {{base_url}}/v1/webhooks/{{webhook_id}}
Authorization: Bearer {{api_key}}
HTTP 204
