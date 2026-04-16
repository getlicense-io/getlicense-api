# =========================================================
# Leases (L2): checkout-based lease lifecycle end-to-end.
# Covers activate with lease token, checkin, idempotent
# re-activate, invalid fingerprint, deactivate, checkin
# after deactivate, and require_checkout=false policy.
# =========================================================

# --- Step 1: signup to get API key ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Leases Test Co",
  "email": "e2e-leases@test.com",
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
  "name": "Leases Product",
  "slug": "leases-product"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Step 3: list policies → capture the auto-seeded default ---
GET {{base_url}}/v1/products/{{product_id}}/policies
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].is_default" == true
[Captures]
default_policy_id: jsonpath "$.data[0].id"

# --- Step 4: PATCH the default policy to enable checkout ---
PATCH {{base_url}}/v1/policies/{{default_policy_id}}
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "require_checkout": true,
  "checkout_interval_sec": 3600,
  "max_checkout_duration_sec": 7200,
  "checkout_grace_sec": 1800
}
HTTP 200
[Asserts]
jsonpath "$.require_checkout" == true
jsonpath "$.checkout_interval_sec" == 3600
jsonpath "$.max_checkout_duration_sec" == 7200
jsonpath "$.checkout_grace_sec" == 1800

# --- Step 5: create license with inline customer ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer": {"email": "lease-holder@example.com", "name": "Lease Holder"}
}
HTTP 201
[Captures]
license_id: jsonpath "$.license.id"

# --- Step 6: activate machine fp-1 ---
POST {{base_url}}/v1/licenses/{{license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fp-1",
  "hostname": "lease-host-1"
}
HTTP 201
[Asserts]
jsonpath "$.machine.status" == "active"
jsonpath "$.machine.fingerprint" == "fp-1"
jsonpath "$.lease_token" matches "^gl2\\."
jsonpath "$.lease_claims.rqc" == true
jsonpath "$.lease_claims.fp" == "fp-1"
[Captures]
machine_id: jsonpath "$.machine.id"

# --- Step 7: checkin fp-1 ---
POST {{base_url}}/v1/licenses/{{license_id}}/machines/fp-1/checkin
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.machine.id" == "{{machine_id}}"
jsonpath "$.machine.status" == "active"
jsonpath "$.lease_token" matches "^gl2\\."

# --- Step 8: idempotent re-activate fp-1 → same machine row ---
POST {{base_url}}/v1/licenses/{{license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fp-1"
}
HTTP 201
[Asserts]
jsonpath "$.machine.id" == "{{machine_id}}"
jsonpath "$.machine.status" == "active"
jsonpath "$.lease_token" matches "^gl2\\."

# --- Step 9: invalid fingerprint → 400 machine_invalid_fingerprint ---
POST {{base_url}}/v1/licenses/{{license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "!!!invalid"
}
HTTP 400
[Asserts]
jsonpath "$.error.code" == "machine_invalid_fingerprint"

# --- Step 10: deactivate fp-1 ---
POST {{base_url}}/v1/licenses/{{license_id}}/deactivate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fp-1"
}
HTTP 204

# --- Step 11: checkin a deactivated machine → 404 machine_not_found ---
POST {{base_url}}/v1/licenses/{{license_id}}/machines/fp-1/checkin
Authorization: Bearer {{api_key}}
HTTP 404
[Asserts]
jsonpath "$.error.code" == "machine_not_found"

# --- Step 12: second policy with require_checkout=false ---
POST {{base_url}}/v1/products/{{product_id}}/policies
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "No Checkout",
  "require_checkout": false
}
HTTP 201
[Asserts]
jsonpath "$.require_checkout" == false
[Captures]
no_checkout_policy_id: jsonpath "$.id"

# Create a license under the no-checkout policy
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "policy_id": "{{no_checkout_policy_id}}",
  "customer": {"email": "no-checkout@example.com", "name": "No Checkout"}
}
HTTP 201
[Captures]
nc_license_id: jsonpath "$.license.id"

# Activate under no-checkout policy → lease_claims.rqc == false
POST {{base_url}}/v1/licenses/{{nc_license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fp-nc-1"
}
HTTP 201
[Asserts]
jsonpath "$.machine.status" == "active"
jsonpath "$.lease_token" matches "^gl2\\."
jsonpath "$.lease_claims.rqc" == false
