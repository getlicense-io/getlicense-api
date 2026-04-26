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
# PR-3.2: response shape is {endpoint: {...}, signing_secret: "..."}
# — the secret is returned ONCE here and never retrievable again.
POST {{base_url}}/v1/webhooks
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "url": "https://example.com/webhook",
  "events": ["license.created", "license.activated"]
}
HTTP 201
[Asserts]
jsonpath "$.endpoint.id" exists
jsonpath "$.endpoint.url" == "https://example.com/webhook"
jsonpath "$.signing_secret" exists
jsonpath "$.signing_secret" matches "^[0-9a-f]{64}$"
[Captures]
webhook_id: jsonpath "$.endpoint.id"
original_signing_secret: jsonpath "$.signing_secret"

# --- List webhook endpoints ---
# Read paths still return the bare endpoint object; the secret is
# never echoed back in any read path.
GET {{base_url}}/v1/webhooks
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" exists
jsonpath "$.has_more" exists
jsonpath "$.data" count >= 1
jsonpath "$.data[0].signing_secret" not exists
jsonpath "$.data[0].signing_secret_encrypted" not exists

# --- Rotate the signing secret ---
# Returns the new plaintext ONCE. The previous secret stops
# validating signatures the moment this returns.
POST {{base_url}}/v1/webhooks/{{webhook_id}}/rotate-signing-secret
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.endpoint.id" == "{{webhook_id}}"
jsonpath "$.signing_secret" exists
jsonpath "$.signing_secret" matches "^[0-9a-f]{64}$"
jsonpath "$.signing_secret" != "{{original_signing_secret}}"

# --- Delete webhook endpoint ---
DELETE {{base_url}}/v1/webhooks/{{webhook_id}}
Authorization: Bearer {{api_key}}
HTTP 204
