# =========================================================
# Full journey: signup → product → license → validate →
#   activate → checkin → suspend → reinstate →
#   deactivate → revoke → validate fails
# =========================================================

# --- Step 1: Signup ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Journey Test Co",
  "email": "e2e-journey@test.com",
  "password": "password123"
}
HTTP 201
[Asserts]
jsonpath "$.account" exists
jsonpath "$.identity" exists
jsonpath "$.api_key" exists
[Captures]
api_key: jsonpath "$.api_key"

# --- Step 2: Create product ---
POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Journey Product",
  "slug": "journey-product"
}
HTTP 201
[Asserts]
jsonpath "$.id" exists
[Captures]
product_id: jsonpath "$.id"

# --- Step 3: Create license ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer": {
    "email": "alice@example.com",
    "name": "Alice Smith"
  }
}
HTTP 201
[Asserts]
jsonpath "$.license.status" == "active"
jsonpath "$.license_key" exists
[Captures]
license_id: jsonpath "$.license.id"
license_key: jsonpath "$.license_key"

# --- Step 4: Validate license (public endpoint) ---
POST {{base_url}}/v1/validate
Content-Type: application/json
{
  "license_key": "{{license_key}}"
}
HTTP 200
[Asserts]
jsonpath "$.valid" == true
jsonpath "$.license.status" == "active"

# --- Step 5: Activate a machine ---
POST {{base_url}}/v1/licenses/{{license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fp-journey-001",
  "hostname": "alice-macbook"
}
HTTP 201
[Asserts]
jsonpath "$.machine.fingerprint" == "fp-journey-001"
jsonpath "$.lease_token" matches "^gl2\\."

# --- Step 6: Checkin ---
POST {{base_url}}/v1/licenses/{{license_id}}/machines/fp-journey-001/checkin
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.machine.fingerprint" == "fp-journey-001"
jsonpath "$.machine.status" == "active"
jsonpath "$.lease_token" matches "^gl2\\."

# --- Step 7: Suspend license ---
POST {{base_url}}/v1/licenses/{{license_id}}/suspend
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.status" == "suspended"

# --- Step 8: Reinstate license ---
POST {{base_url}}/v1/licenses/{{license_id}}/reinstate
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.status" == "active"

# --- Step 9: Deactivate machine ---
POST {{base_url}}/v1/licenses/{{license_id}}/deactivate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fp-journey-001"
}
HTTP 204

# --- Step 10: Revoke license ---
DELETE {{base_url}}/v1/licenses/{{license_id}}
Authorization: Bearer {{api_key}}
HTTP 204

# --- Step 11: Validate revoked license — returns error ---
POST {{base_url}}/v1/validate
Content-Type: application/json
{
  "license_key": "{{license_key}}"
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "license_revoked"
