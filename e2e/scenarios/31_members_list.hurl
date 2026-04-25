# 31_members_list.hurl — verify GET /v1/accounts/:account_id/members
# returns the team roster with the right shape and excludes secret
# fields. Covers the owner-listing-themselves case, the
# owner-listing-themselves-plus-an-invited-developer case, and the
# path-mismatch case (caller's acting account != path account).
#
# Note: the path-mismatch step expects HTTP 422 validation_error per
# requirePathAccountMatch (auth_helpers.go) — same convention as
# 18_grants.hurl:252-256. The rbac.UserList gate already prevents
# arbitrary callers from probing foreign accounts, so there is no
# existence-leak vector to defend against with a 404 collapse.

# --- Owner signup ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Members E2E Co",
  "email": "e2e-members-owner@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
owner_token: jsonpath "$.access_token"
owner_account_id: jsonpath "$.account.id"

# --- List members: just the owner ---
GET {{base_url}}/v1/accounts/{{owner_account_id}}/members
Authorization: Bearer {{owner_token}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 1
jsonpath "$.data[0].identity.email" == "e2e-members-owner@test.com"
jsonpath "$.data[0].role.slug" == "owner"
jsonpath "$.data[0].role.name" exists
jsonpath "$.data[0].membership_id" exists
jsonpath "$.data[0].joined_at" exists
jsonpath "$.has_more" == false
# Secret-field exclusion — defense in depth.
body not contains "password"
body not contains "password_hash"
body not contains "totp_secret"
body not contains "totp_verified_at"

# --- Owner invites a developer ---
POST {{base_url}}/v1/accounts/{{owner_account_id}}/invitations
Authorization: Bearer {{owner_token}}
Content-Type: application/json
{
  "email": "e2e-members-dev@test.com",
  "role_slug": "developer"
}
HTTP 201
[Captures]
invite_token: jsonpath "$.accept_url" regex "/invitations/(.+)$"

# --- Recipient signs up to get an identity ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Dev Personal",
  "email": "e2e-members-dev@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
dev_token: jsonpath "$.access_token"

# --- Recipient accepts the invitation ---
POST {{base_url}}/v1/invitations/{{invite_token}}/accept
Authorization: Bearer {{dev_token}}
HTTP 200

# --- Owner lists members again: now both ---
GET {{base_url}}/v1/accounts/{{owner_account_id}}/members
Authorization: Bearer {{owner_token}}
HTTP 200
[Asserts]
jsonpath "$.data" count == 2
jsonpath "$.data[*].identity.email" contains "e2e-members-owner@test.com"
jsonpath "$.data[*].identity.email" contains "e2e-members-dev@test.com"
jsonpath "$.data[*].role.slug" contains "owner"
jsonpath "$.data[*].role.slug" contains "developer"

# --- Path mismatch: caller's acting account does not equal the path
#     account (sends a random UUID). requirePathAccountMatch returns
#     422 validation_error per the convention at 18_grants.hurl:252-256.
GET {{base_url}}/v1/accounts/00000000-0000-0000-0000-000000000000/members
Authorization: Bearer {{owner_token}}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "validation_error"
