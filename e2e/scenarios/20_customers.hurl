# =========================================================
# Customers (L4): direct vendor CRUD, license attach via
# customer_id vs inline customer (upsert idempotency),
# in-use delete block, validation errors, PATCH reassign.
# =========================================================

# --- Step 1: signup to get API key ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Customers Test Co",
  "email": "e2e-customers@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
api_key: jsonpath "$.api_key"

# --- Step 2: direct customer create (vendor path). No grant,
#     so created_by_account_id is null and will NOT appear in
#     the JSON response (omitempty on a nil pointer). ---
POST {{base_url}}/v1/customers
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "email": "alice@example.com",
  "name": "Alice"
}
HTTP 201
[Asserts]
jsonpath "$.id" exists
jsonpath "$.email" == "alice@example.com"
jsonpath "$.name" == "Alice"
jsonpath "$.created_by_account_id" not exists
[Captures]
customer_id: jsonpath "$.id"

# --- Step 3: GET the customer by id ---
GET {{base_url}}/v1/customers/{{customer_id}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{customer_id}}"
jsonpath "$.email" == "alice@example.com"
jsonpath "$.name" == "Alice"

# --- Step 4: list customers — direct-create path has no
#     created_by_account_id (omitempty hides nil). ---
GET {{base_url}}/v1/customers
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].id" == "{{customer_id}}"
jsonpath "$.data[0].created_by_account_id" not exists

# --- Step 5: case-insensitive prefix filter on ?email= ---
GET {{base_url}}/v1/customers?email=alic
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].id" == "{{customer_id}}"

# --- Step 6: create a product so we can attach licenses ---
POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Customer Test Product",
  "slug": "customer-test-product"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Step 7: create a license attaching the existing customer
#     via customer_id. The license.customer_id must match. ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer_id": "{{customer_id}}"
}
HTTP 201
[Asserts]
jsonpath "$.license.customer_id" == "{{customer_id}}"
[Captures]
first_license_id: jsonpath "$.license.id"

# --- Step 8: create a second license using inline customer
#     block with the SAME email but a DIFFERENT name. The
#     upsert-by-email is first-write-wins, so the same
#     customer row is reused (customer_id matches), and Alice's
#     name is NOT overwritten. ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer": {
    "email": "alice@example.com",
    "name": "Different"
  }
}
HTTP 201
[Asserts]
jsonpath "$.license.customer_id" == "{{customer_id}}"
[Captures]
second_license_id: jsonpath "$.license.id"

# Verify name was not overwritten on the existing customer.
GET {{base_url}}/v1/customers/{{customer_id}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.name" == "Alice"

# --- Step 9: list-licenses-by-customer returns both licenses ---
GET {{base_url}}/v1/customers/{{customer_id}}/licenses
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 2

# --- Step 10: delete is refused while licenses reference
#     the customer — 409 customer_in_use. ---
DELETE {{base_url}}/v1/customers/{{customer_id}}
Authorization: Bearer {{api_key}}
HTTP 409
[Asserts]
jsonpath "$.error.code" == "customer_in_use"

# --- Step 11: malformed email on direct create → 422
#     customer_invalid_email. ---
POST {{base_url}}/v1/customers
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "email": "not-an-email"
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "customer_invalid_email"

# --- Step 12: creating a license with BOTH customer_id AND
#     inline customer → 422 customer_ambiguous. ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer_id": "{{customer_id}}",
  "customer": {"email": "alice@example.com"}
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "customer_ambiguous"

# --- Step 13: creating a license with NEITHER customer_id NOR
#     inline customer → 422 customer_required. ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "customer_required"

# --- Step 14: create a second customer bob ---
POST {{base_url}}/v1/customers
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "email": "bob@example.com",
  "name": "Bob"
}
HTTP 201
[Captures]
bob_id: jsonpath "$.id"

# --- Step 15: PATCH the first license to reassign to bob ---
PATCH {{base_url}}/v1/licenses/{{first_license_id}}
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer_id": "{{bob_id}}"
}
HTTP 200
[Asserts]
jsonpath "$.customer_id" == "{{bob_id}}"

# --- Step 16: update (PATCH) customer name via vendor endpoint ---
PATCH {{base_url}}/v1/customers/{{customer_id}}
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Alice Updated"
}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{customer_id}}"
jsonpath "$.name" == "Alice Updated"

# --- Step 17: revoke both licenses, then delete customers.
#     Revoking flips status to `revoked` but does NOT detach
#     the customer — customer_in_use is still true until the
#     license rows are gone. The scenario asserts the 409
#     state; actual hard-deletion of licenses is out of scope. ---
DELETE {{base_url}}/v1/licenses/{{first_license_id}}
Authorization: Bearer {{api_key}}
HTTP 204

DELETE {{base_url}}/v1/licenses/{{second_license_id}}
Authorization: Bearer {{api_key}}
HTTP 204

# Alice is still referenced by the (revoked) licenses — still 409.
DELETE {{base_url}}/v1/customers/{{customer_id}}
Authorization: Bearer {{api_key}}
HTTP 409
[Asserts]
jsonpath "$.error.code" == "customer_in_use"

# Bob is still referenced by the first license (reassigned earlier,
# now revoked) — also still 409.
DELETE {{base_url}}/v1/customers/{{bob_id}}
Authorization: Bearer {{api_key}}
HTTP 409
[Asserts]
jsonpath "$.error.code" == "customer_in_use"
