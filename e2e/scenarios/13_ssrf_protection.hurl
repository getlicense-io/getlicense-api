# =========================================================
# SSRF protection: webhook URL validation.
# Server runs in development mode for e2e, so HTTP/localhost
# are allowed. Non-HTTP schemes are always rejected.
# =========================================================

# --- Setup: signup ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "SSRF Test Co",
  "email": "e2e-ssrf@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
api_key: jsonpath "$.api_key"

# --- Reject ftp:// scheme ---
POST {{base_url}}/v1/webhooks
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "url": "ftp://example.com/hook"
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# --- Allow http://localhost in development mode ---
# PR-3.2: response is wrapped {endpoint, signing_secret}.
POST {{base_url}}/v1/webhooks
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "url": "http://localhost:9999/hook"
}
HTTP 201
[Asserts]
jsonpath "$.endpoint.url" == "http://localhost:9999/hook"
[Captures]
webhook_id: jsonpath "$.endpoint.id"

# --- Allow https:// ---
POST {{base_url}}/v1/webhooks
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "url": "https://example.com/webhook"
}
HTTP 201
[Asserts]
jsonpath "$.endpoint.url" == "https://example.com/webhook"

# --- Cleanup ---
DELETE {{base_url}}/v1/webhooks/{{webhook_id}}
Authorization: Bearer {{api_key}}
HTTP 204
