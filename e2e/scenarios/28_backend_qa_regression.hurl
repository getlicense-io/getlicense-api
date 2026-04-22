# =========================================================
# Backend-QA audit regression suite (sqlc branch).
#
# Consolidates the regression coverage for the findings that
# did not fit naturally into the existing per-feature scenarios:
#
#   M5 — pgx session TZ was not pinned to UTC, so GET returned
#        +05:30-suffixed timestamps while POST returned `Z`.
#   L7 — non-standard HTTP verbs (QUERY, LINK, UNLINK, ...)
#        landed on 501 Not Implemented; convention is 405.
#   L8 — malformed cursor returned 422 validation_error; a
#        garbage opaque value is a client bug → 400 invalid_cursor.
#
# H1 / H2 / M3 / M4 / L6 regressions live alongside the feature
# scenarios (19_policies.hurl, 20_customers.hurl, 27_auth_switch.hurl).
# =========================================================

# --- Tenant setup: one signup yields an API key we reuse below. ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Backend QA Regression Co",
  "email": "e2e-backend-qa@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
api_key: jsonpath "$.api_key"

# =========================================================
# M5 — timezone drift. Create a customer, then GET it. Before
# the pool-level `timezone=UTC` pin, the POST response came from
# Go's time.Now().UTC() (always ...Z) while the GET came from
# pgx rendering `timestamptz` through the session TZ, which
# produced `...+05:30` on machines whose Postgres container
# carried a non-UTC default. Asserting the created_at ends with
# `Z` on both the POST response and the subsequent GET catches
# the regression without coupling to the specific timestamp.
# =========================================================
POST {{base_url}}/v1/customers
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "email": "tz-check@example.com"
}
HTTP 201
[Captures]
tz_customer_id: jsonpath "$.id"
tz_created_at_post: jsonpath "$.created_at"
[Asserts]
jsonpath "$.created_at" matches "Z$"

GET {{base_url}}/v1/customers/{{tz_customer_id}}
Authorization: Bearer {{api_key}}
HTTP 200
[Asserts]
jsonpath "$.created_at" matches "Z$"
jsonpath "$.created_at" == "{{tz_created_at_post}}"

# =========================================================
# L7 — non-standard HTTP verbs now land on 405 (method not
# allowed) with the typed envelope, not a bare 501. Authenticated
# with the API key so the response reflects the routing layer
# rather than an auth short-circuit.
# =========================================================
QUERY {{base_url}}/v1/customers
Authorization: Bearer {{api_key}}
HTTP 405
[Asserts]
jsonpath "$.error.code" == "method_not_allowed"

LINK {{base_url}}/v1/customers/{{tz_customer_id}}
Authorization: Bearer {{api_key}}
HTTP 405
[Asserts]
jsonpath "$.error.code" == "method_not_allowed"

# =========================================================
# L8 — malformed cursor is a client-side bug. Before the fix,
# DecodeCursor errors mapped to ErrValidationError → 422. A
# garbled base64 value is semantically "you sent garbage",
# which HTTP codifies as 400 Bad Request.
# =========================================================
GET {{base_url}}/v1/customers?cursor=not-base64!!!
Authorization: Bearer {{api_key}}
HTTP 400
[Asserts]
jsonpath "$.error.code" == "invalid_cursor"

# Valid base64 but missing cursor fields (t,i) is still invalid.
# "e30" is base64url("{}"). Previously silently treated as page 1
# in some code paths — after F-006 it rejects, and after L8 the
# rejection is 400 invalid_cursor.
GET {{base_url}}/v1/customers?cursor=e30
Authorization: Bearer {{api_key}}
HTTP 400
[Asserts]
jsonpath "$.error.code" == "invalid_cursor"
