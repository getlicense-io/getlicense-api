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

# --- Setup: create license with max_machines=1 ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "license_type": "perpetual",
  "max_machines": 1
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
HTTP 201
[Asserts]
jsonpath "$.fingerprint" == "fp-machine-001"
jsonpath "$.hostname" == "workstation-001"

# --- Duplicate activation with same fingerprint returns 409 ---
POST {{base_url}}/v1/licenses/{{license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fp-machine-001"
}
HTTP 409
[Asserts]
jsonpath "$.error.code" == "machine_already_activated"

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

# --- Heartbeat ---
POST {{base_url}}/v1/licenses/{{license_id}}/heartbeat
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fp-machine-001"
}
HTTP 200
[Asserts]
jsonpath "$.fingerprint" == "fp-machine-001"

# --- Deactivate machine ---
POST {{base_url}}/v1/licenses/{{license_id}}/deactivate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fp-machine-001"
}
HTTP 204
