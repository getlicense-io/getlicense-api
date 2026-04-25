# =========================================================
# Events CSV export (Task 21): GET /v1/events?format=csv.
# Covers:
#  - Content negotiation via `?format=csv` query param.
#  - Content negotiation via `Accept: text/csv` header.
#  - Content-Type and Content-Disposition headers on CSV response.
#  - The frozen 14-column header line.
#  - At least one license.created event row appears in the CSV.
#  - Default path (no format, no Accept) still returns JSON.
#  - Filter that excludes all rows still returns a valid CSV
#    with just the header line.
# =========================================================

# --- Step 1: vendor signup (returns api_key for API auth) ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "CSV Export Vendor",
  "email": "e2e-csv-vendor@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
api_key: jsonpath "$.api_key"

# --- Step 2: create a product (emits product.created event) ---
POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "CSV Widget",
  "slug": "csv-widget"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Step 3: create a license (emits license.created event) ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer": {"email": "e2e-csv-buyer@test.com"}
}
HTTP 201

# --- Step 4: CSV mode via ?format=csv query param ---
GET {{base_url}}/v1/events?format=csv
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
header "Content-Type" contains "text/csv"
header "Content-Disposition" contains "attachment"
header "Content-Disposition" contains "events_"
# Frozen 14-column header line must be the exact first line.
body startsWith "id,created_at,event_type,resource_type,resource_id,actor_kind,actor_label,acting_account_id,identity_id,api_key_id,grant_id,request_id,ip_address,payload_json"
# At least one license.created event row in the export.
body contains "license.created"

# --- Step 5: CSV mode via Accept: text/csv header ---
GET {{base_url}}/v1/events
Authorization: Bearer {{api_key}}
Accept: text/csv
HTTP 200
[Asserts]
header "Content-Type" contains "text/csv"
header "Content-Disposition" contains "attachment"
body startsWith "id,created_at,event_type,resource_type,resource_id,actor_kind,actor_label,acting_account_id,identity_id,api_key_id,grant_id,request_id,ip_address,payload_json"

# --- Step 6: default path (no format, no CSV Accept) still returns JSON.
#     Regression guard for existing consumers. ---
GET {{base_url}}/v1/events
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.data" exists

# --- Step 7: filter with a future from-date returns zero data rows
#     but still a valid CSV with just the header line. ---
GET {{base_url}}/v1/events?format=csv&from=2099-01-01T00:00:00Z
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
header "Content-Type" contains "text/csv"
body startsWith "id,created_at,event_type,resource_type,resource_id,actor_kind,actor_label,acting_account_id,identity_id,api_key_id,grant_id,request_id,ip_address,payload_json"
