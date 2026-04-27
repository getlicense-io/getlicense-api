# 17_invitations.hurl — membership invitation round-trip
#
# Flow:
#   1. Identity A signs up → gets account A + JWT
#   2. A issues a membership invitation for a fresh email
#   3. Lookup the token unauthenticated → returns preview
#   4. Identity B signs up with the invited email
#   5. B accepts the invitation → becomes member of A
#   6. GET /auth/me on B → shows 2 memberships (own account + A)

# Step 1: signup identity A
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Inviter Co",
  "email": "e2e-inviter@test.com",
  "password": "password123"
}

HTTP 201
[Captures]
inviter_token: jsonpath "$.access_token"
inviter_account_id: jsonpath "$.account.id"

# Step 2: issue a membership invitation for a fresh email
POST {{base_url}}/v1/accounts/{{inviter_account_id}}/invitations
Authorization: Bearer {{inviter_token}}
Content-Type: application/json
{
  "email": "e2e-invitee@test.com",
  "role_slug": "admin"
}

HTTP 201
[Asserts]
jsonpath "$.invitation.kind" == "membership"
jsonpath "$.invitation.email" == "e2e-invitee@test.com"
jsonpath "$.accept_url" matches "/invitations/"
[Captures]
raw_token: jsonpath "$.accept_url" regex "/invitations/(.+)$"

# Step 3: preview the invitation unauthenticated. The lookup must embed
# grantor_account (id, name, slug) so the dashboard accept page can
# render the inviting account without a follow-up authenticated fetch.
GET {{base_url}}/v1/invitations/{{raw_token}}/lookup

HTTP 200
[Asserts]
jsonpath "$.kind" == "membership"
jsonpath "$.email" == "e2e-invitee@test.com"
jsonpath "$.account_name" == "Inviter Co"
jsonpath "$.role_name" == "Admin"
jsonpath "$.grantor_account.name" == "Inviter Co"
jsonpath "$.grantor_account.id" exists
jsonpath "$.grantor_account.slug" exists

# Step 4: signup identity B with the invited email
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Invitee Co",
  "email": "e2e-invitee@test.com",
  "password": "password123"
}

HTTP 201
[Captures]
invitee_token: jsonpath "$.access_token"

# Step 5: accept the invitation as identity B
POST {{base_url}}/v1/invitations/{{raw_token}}/accept
Authorization: Bearer {{invitee_token}}

HTTP 200
[Asserts]
jsonpath "$.membership_id" exists
jsonpath "$.account_id" == "{{inviter_account_id}}"

# Step 6: /auth/me on B now shows 2 memberships
GET {{base_url}}/v1/auth/me
Authorization: Bearer {{invitee_token}}

HTTP 200
[Asserts]
jsonpath "$.memberships" count >= 2

# ── Grant-kind invitation round-trip ─────────────────────────────────
# Regression for backend-qa finding: POST /v1/accounts/:id/invitations
# must dispatch on body shape (role_slug vs grant_draft), not bind
# every request to CreateMembershipRequest. Previously a grant-kind
# payload returned 422 "role_slug required".

# Step 7: inviter creates a product for the grant to target
POST {{base_url}}/v1/products
Authorization: Bearer {{inviter_token}}
Content-Type: application/json
{
  "name": "Grant Target",
  "slug": "grant-target-inv"
}

HTTP 201
[Captures]
grant_product_id: jsonpath "$.id"

# Step 8: inviter issues a grant-kind invitation to a fresh email
POST {{base_url}}/v1/accounts/{{inviter_account_id}}/invitations
Authorization: Bearer {{inviter_token}}
Content-Type: application/json
{
  "kind": "grant",
  "email": "e2e-grantinvite@test.com",
  "grant_draft": {
    "product_id": "{{grant_product_id}}",
    "capabilities": ["LICENSE_CREATE", "LICENSE_READ"]
  }
}

HTTP 201
[Asserts]
jsonpath "$.invitation.kind" == "grant"
jsonpath "$.invitation.email" == "e2e-grantinvite@test.com"
jsonpath "$.accept_url" matches "/invitations/"
[Captures]
grant_raw_token: jsonpath "$.accept_url" regex "/invitations/(.+)$"

# Step 9: preview the grant-kind invitation
GET {{base_url}}/v1/invitations/{{grant_raw_token}}/lookup

HTTP 200
[Asserts]
jsonpath "$.kind" == "grant"
jsonpath "$.email" == "e2e-grantinvite@test.com"

# Step 10: fresh identity signs up with the invited email
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Grant Invitee Co",
  "email": "e2e-grantinvite@test.com",
  "password": "password123"
}

HTTP 201
[Captures]
grant_invitee_token: jsonpath "$.access_token"
grant_invitee_account_id: jsonpath "$.account.id"

# Step 11: accept the grant-kind invitation
POST {{base_url}}/v1/invitations/{{grant_raw_token}}/accept
Authorization: Bearer {{grant_invitee_token}}

HTTP 200
[Asserts]
jsonpath "$.grant_id" exists
jsonpath "$.membership_id" not exists
jsonpath "$.account_id" == "{{grant_invitee_account_id}}"

# Step 12: validation — missing both role_slug and grant_draft → 422
POST {{base_url}}/v1/accounts/{{inviter_account_id}}/invitations
Authorization: Bearer {{inviter_token}}
Content-Type: application/json
{
  "email": "e2e-empty@test.com"
}

HTTP 422

# Step 13: validation — both role_slug and grant_draft → 422
POST {{base_url}}/v1/accounts/{{inviter_account_id}}/invitations
Authorization: Bearer {{inviter_token}}
Content-Type: application/json
{
  "email": "e2e-ambiguous@test.com",
  "role_slug": "admin",
  "grant_draft": {
    "product_id": "{{grant_product_id}}",
    "capabilities": ["LICENSE_READ"]
  }
}

HTTP 422
