# --- Setup: signup to get API key ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Machines Test Co",
  "email": "e2e-machines@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
api_key: jsonpath "$.api_key"

# --- Setup: create product ---
POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Machines Product",
  "slug": "machines-product"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Setup: create license with max_machines=1 (per-license override) ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "overrides": { "max_machines": 1 },
  "customer": {"email": "machines@example.com"}
}
HTTP 201
[Captures]
license_id: jsonpath "$.license.id"

# --- Activate first machine ---
POST {{base_url}}/v1/licenses/{{license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fp-machine-001",
  "hostname": "workstation-001"
}
HTTP 200
[Asserts]
jsonpath "$.machine.fingerprint" == "fp-machine-001"
jsonpath "$.machine.hostname" == "workstation-001"
jsonpath "$.machine.status" == "active"
jsonpath "$.lease_token" matches "^gl2\\."
[Captures]
machine_id: jsonpath "$.machine.id"

# --- Idempotent re-activate with same fingerprint returns 201 (same machine) ---
POST {{base_url}}/v1/licenses/{{license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fp-machine-001"
}
HTTP 200
[Asserts]
jsonpath "$.machine.id" == "{{machine_id}}"
jsonpath "$.machine.fingerprint" == "fp-machine-001"
jsonpath "$.machine.status" == "active"
jsonpath "$.lease_token" matches "^gl2\\."

# --- Machine limit exceeded with different fingerprint returns 422 ---
POST {{base_url}}/v1/licenses/{{license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fp-machine-002"
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "machine_limit_exceeded"

# --- Checkin ---
POST {{base_url}}/v1/licenses/{{license_id}}/machines/fp-machine-001/checkin
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.machine.fingerprint" == "fp-machine-001"
jsonpath "$.machine.status" == "active"
jsonpath "$.lease_token" matches "^gl2\\."

# --- Deactivate machine ---
POST {{base_url}}/v1/licenses/{{license_id}}/deactivate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fp-machine-001"
}
HTTP 204
