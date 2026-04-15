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

# Step 3: preview the invitation unauthenticated
GET {{base_url}}/v1/invitations/{{raw_token}}/lookup

HTTP 200
[Asserts]
jsonpath "$.kind" == "membership"
jsonpath "$.email" == "e2e-invitee@test.com"
jsonpath "$.account_name" == "Inviter Co"
jsonpath "$.role_name" == "Admin"

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
