# =========================================================
# Metrics Snapshot (O4): GET /v1/metrics returns KPI counts
# and daily event buckets.
# =========================================================

# --- Step 1: signup to get API key ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Metrics Test Co",
  "email": "e2e-metrics@test.com",
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
  "name": "Metrics Product",
  "slug": "metrics-product"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Step 3: create customer ---
POST {{base_url}}/v1/customers
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "email": "metrics-cust@example.com",
  "name": "Metrics Customer"
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

# --- Step 5: GET /v1/metrics — default 30-day range ---
GET {{base_url}}/v1/metrics
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.licenses.total" >= 1
jsonpath "$.licenses.active" >= 1
jsonpath "$.machines.total" >= 0
jsonpath "$.customers.total" >= 1
jsonpath "$.grants.active_grants" >= 0
jsonpath "$.grants.licenses_via_grants" >= 0
jsonpath "$.events_by_day" count >= 1

# --- Step 6: GET /v1/metrics with explicit from/to ---
GET {{base_url}}/v1/metrics?from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.licenses.total" >= 1
jsonpath "$.events_by_day" count >= 1

# --- Step 7: validation — to before from ---
GET {{base_url}}/v1/metrics?from=2099-01-01T00:00:00Z&to=2020-01-01T00:00:00Z
Authorization: Bearer {{api_key}}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# --- Step 8: validation — range exceeds 365 days ---
GET {{base_url}}/v1/metrics?from=2020-01-01T00:00:00Z&to=2025-01-01T00:00:00Z
Authorization: Bearer {{api_key}}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"
