# =========================================================
# Policies (L1): product auto-default, secondary policy,
# promotion, freeze, policy update cascade vs frozen
# override isolation, and default-delete guard.
# =========================================================

# --- Step 1: signup to get API key ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Policies Test Co",
  "email": "e2e-policies@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
api_key: jsonpath "$.api_key"

# --- Step 2: create a product — product creation auto-seeds a
#     single default policy named "Default" for that product. ---
POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Policies Product",
  "slug": "policies-product"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Step 3: list policies for the product → exactly one row,
#     and that row is the auto-seeded default. ---
GET {{base_url}}/v1/products/{{product_id}}/policies
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].is_default" == true
jsonpath "$.data[0].name" == "Default"
[Captures]
default_policy_id: jsonpath "$.data[0].id"

# --- Step 4: create a second "Premium" policy with a
#     non-default cap of max_machines=2. Not marked default. ---
POST {{base_url}}/v1/products/{{product_id}}/policies
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Premium",
  "max_machines": 2
}
HTTP 201
[Asserts]
jsonpath "$.name" == "Premium"
jsonpath "$.is_default" == false
jsonpath "$.max_machines" == 2
[Captures]
premium_policy_id: jsonpath "$.id"

# --- Step 5: promote Premium to default. The old Default is
#     demoted in the same transaction. ---
POST {{base_url}}/v1/policies/{{premium_policy_id}}/set-default
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{premium_policy_id}}"
jsonpath "$.is_default" == true

# --- Step 6: listing policies now shows both, Premium is default,
#     Default is demoted. Order is (created_at DESC, id DESC),
#     so Premium (created second) comes first. ---
GET {{base_url}}/v1/products/{{product_id}}/policies
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 2
jsonpath "$.data[0].id" == "{{premium_policy_id}}"
jsonpath "$.data[0].is_default" == true
jsonpath "$.data[1].id" == "{{default_policy_id}}"
jsonpath "$.data[1].is_default" == false

# --- Step 7: create a license explicitly attached to Premium.
#     No overrides; inherits max_machines=2 from the policy. ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "policy_id": "{{premium_policy_id}}",
  "customer": {"email": "frozen@example.com", "name": "Frozen License"}
}
HTTP 201
[Asserts]
jsonpath "$.license.policy_id" == "{{premium_policy_id}}"
[Captures]
frozen_license_id: jsonpath "$.license.id"

# --- Step 8: freeze the license. The response is the full
#     license; overrides.max_machines is now snapshotted to 2. ---
POST {{base_url}}/v1/licenses/{{frozen_license_id}}/freeze
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{frozen_license_id}}"
jsonpath "$.overrides.max_machines" == 2
jsonpath "$.overrides.checkout_interval_sec" exists
jsonpath "$.overrides.max_checkout_duration_sec" exists

# --- Step 9: update Premium — raise max_machines to 4. The
#     frozen license keeps its override, so its effective cap
#     stays 2; a fresh license under Premium gets 4. ---
PATCH {{base_url}}/v1/policies/{{premium_policy_id}}
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "max_machines": 4
}
HTTP 200
[Asserts]
jsonpath "$.max_machines" == 4

# The frozen license still carries the snapshotted override —
# future policy changes no longer cascade into it.
GET {{base_url}}/v1/licenses/{{frozen_license_id}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.overrides.max_machines" == 2

# --- Step 10: observe the cap is still 2 on the frozen license
#     by activating machines: two succeed, the third fails with
#     machine_limit_exceeded. ---
POST {{base_url}}/v1/licenses/{{frozen_license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "frozen-fp-1"
}
HTTP 201

POST {{base_url}}/v1/licenses/{{frozen_license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "frozen-fp-2"
}
HTTP 201

POST {{base_url}}/v1/licenses/{{frozen_license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "frozen-fp-3"
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "machine_limit_exceeded"

# --- Step 11: a fresh license on the same policy, post-update,
#     enforces the new cap (4). Four activations succeed; the
#     fifth fails. ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "policy_id": "{{premium_policy_id}}",
  "customer": {"email": "fresh@example.com", "name": "Fresh License"}
}
HTTP 201
[Captures]
fresh_license_id: jsonpath "$.license.id"

POST {{base_url}}/v1/licenses/{{fresh_license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fresh-fp-1"
}
HTTP 201

POST {{base_url}}/v1/licenses/{{fresh_license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fresh-fp-2"
}
HTTP 201

POST {{base_url}}/v1/licenses/{{fresh_license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fresh-fp-3"
}
HTTP 201

POST {{base_url}}/v1/licenses/{{fresh_license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fresh-fp-4"
}
HTTP 201

POST {{base_url}}/v1/licenses/{{fresh_license_id}}/activate
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "fingerprint": "fresh-fp-5"
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "machine_limit_exceeded"

# --- Step 12: GET /v1/policies/:id — happy path returns the
#     policy with all its configured fields. ---
GET {{base_url}}/v1/policies/{{default_policy_id}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{default_policy_id}}"
jsonpath "$.name" == "Default"
jsonpath "$.product_id" == "{{product_id}}"
jsonpath "$.is_default" == false

# --- Step 13: GET /v1/policies/:id for a bogus id → 404. ---
GET {{base_url}}/v1/policies/00000000-0000-0000-0000-000000000000
Authorization: Bearer {{api_key}}
HTTP 404
[Asserts]
jsonpath "$.error.code" == "policy_not_found"

# --- Step 14: attach-policy happy path — move fresh_license_id
#     from Premium back to the old (non-default) Default policy
#     within the same product, clearing overrides in the same
#     transaction. License policy_id now equals default_policy_id. ---
POST {{base_url}}/v1/licenses/{{fresh_license_id}}/attach-policy
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "policy_id": "{{default_policy_id}}",
  "clear_overrides": true
}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{fresh_license_id}}"
jsonpath "$.policy_id" == "{{default_policy_id}}"

# --- Step 15: attach-policy cross-product negative — create a
#     SECOND product (with its own auto-seeded default policy) and
#     try to attach that policy to a license from the first
#     product. Must be rejected with policy_product_mismatch (422). ---
POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Other Product",
  "slug": "other-product"
}
HTTP 201
[Captures]
other_product_id: jsonpath "$.id"

GET {{base_url}}/v1/products/{{other_product_id}}/policies
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].is_default" == true
[Captures]
other_default_policy_id: jsonpath "$.data[0].id"

POST {{base_url}}/v1/licenses/{{fresh_license_id}}/attach-policy
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "policy_id": "{{other_default_policy_id}}"
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "policy_product_mismatch"

# --- Step 16: deleting the current default policy is rejected
#     with policy_is_default (422). The old Default is now
#     non-default but was reattached in step 14, so a plain
#     delete is refused with policy_in_use; force=true reassigns
#     referencing licenses back to the current default (Premium)
#     and completes the delete. ---
DELETE {{base_url}}/v1/policies/{{premium_policy_id}}
Authorization: Bearer {{api_key}}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "policy_is_default"

DELETE {{base_url}}/v1/policies/{{default_policy_id}}
Authorization: Bearer {{api_key}}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "policy_in_use"

DELETE {{base_url}}/v1/policies/{{default_policy_id}}?force=true
Authorization: Bearer {{api_key}}
HTTP 204

# =========================================================
# Regression scenarios (backend-qa audit, sqlc branch)
# =========================================================

# --- H2: POST /v1/products/:bogus/policies must return 404
#     product_not_found, not 500. Before the FK-classification
#     fix, the policy-insert 23503 bubbled as a raw pg error. ---
POST {{base_url}}/v1/products/00000000-0000-0000-0000-000000000000/policies
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Bogus Parent"
}
HTTP 404
[Asserts]
jsonpath "$.error.code" == "product_not_found"

# --- M4: GET /v1/products/:bogus/policies must return 404
#     product_not_found, not 200 {"data":[]}. Silent empty
#     lists masked BOLA-lite probes. ---
GET {{base_url}}/v1/products/00000000-0000-0000-0000-000000000000/policies
Authorization: Bearer {{api_key}}
HTTP 404
[Asserts]
jsonpath "$.error.code" == "product_not_found"

# --- M3: POST /v1/products/:id/policies with empty name → 422. ---
POST {{base_url}}/v1/products/{{other_product_id}}/policies
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": ""
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# --- M3: negative max_machines → 422. ---
POST {{base_url}}/v1/products/{{other_product_id}}/policies
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Negative",
  "max_machines": -1
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# --- M3: zero max_seats → 422 (must be >= 1). ---
POST {{base_url}}/v1/products/{{other_product_id}}/policies
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Zero Seats",
  "max_seats": 0
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"

# --- H2 / BOLA: cross-tenant product UUID on POST / GET policies.
#     Tenant B creates a product, tenant A probes it. Postgres FK
#     checks bypass RLS, so without the RLS-scoped pre-check in
#     PolicyHandler.Create, tenant A could insert a policy under a
#     tenant-B product id (account_id = A, product_id = B leak).
#     The pre-check collapses "doesn't exist" and "belongs to
#     someone else" into the same 404. ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Policies Leak Probe Co",
  "email": "e2e-policies-leak@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
tenant_b_key: jsonpath "$.api_key"

POST {{base_url}}/v1/products
Authorization: Bearer {{tenant_b_key}}
Content-Type: application/json
{
  "name": "Tenant B Product",
  "slug": "tenant-b-product"
}
HTTP 201
[Captures]
tenant_b_product_id: jsonpath "$.id"

# Tenant A attempts to create a policy under tenant B's product.
POST {{base_url}}/v1/products/{{tenant_b_product_id}}/policies
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "Cross-tenant leak"
}
HTTP 404
[Asserts]
jsonpath "$.error.code" == "product_not_found"

# Tenant A listing policies for tenant B's product — same 404.
GET {{base_url}}/v1/products/{{tenant_b_product_id}}/policies
Authorization: Bearer {{api_key}}
HTTP 404
[Asserts]
jsonpath "$.error.code" == "product_not_found"
