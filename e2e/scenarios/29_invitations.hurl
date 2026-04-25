# 29_invitations.hurl — Sharing v2 invitation lifecycle
#
# Covers the new Sharing v2 invitation endpoints:
#   - GET  /v1/accounts/:account_id/invitations  (list with kind/status filters)
#   - GET  /v1/invitations/:invitation_id         (single, no accept_url)
#   - POST /v1/invitations/:invitation_id/resend  (regenerate token, invalidate old)
#   - DELETE /v1/invitations/:invitation_id       (hard-delete, event before delete)
# plus the event audit trail covering invitation.created / .resent / .revoked.

# Step 1: signup identity A → account + JWT
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Sharing v2 Inviter",
  "email": "e2e-sv2-inviter@test.com",
  "password": "password123"
}

HTTP 201
[Captures]
inviter_token: jsonpath "$.access_token"
inviter_account_id: jsonpath "$.account.id"

# Step 2: issue a membership invitation (fresh email)
POST {{base_url}}/v1/accounts/{{inviter_account_id}}/invitations
Authorization: Bearer {{inviter_token}}
Content-Type: application/json
{
  "email": "e2e-sv2-invitee-1@test.com",
  "role_slug": "admin"
}

HTTP 201
[Asserts]
jsonpath "$.invitation.kind" == "membership"
jsonpath "$.invitation.email" == "e2e-sv2-invitee-1@test.com"
jsonpath "$.accept_url" matches "/invitations/"
[Captures]
inv_id: jsonpath "$.invitation.id"
old_accept_url: jsonpath "$.accept_url"
old_raw_token: jsonpath "$.accept_url" regex "/invitations/(.+)$"

# Step 3: list invitations with status=pending → AccountSummary embed + status
# are populated on the read path (JOIN), not on the create response.
GET {{base_url}}/v1/accounts/{{inviter_account_id}}/invitations?status=pending
Authorization: Bearer {{inviter_token}}

HTTP 200
[Asserts]
jsonpath "$.data" count >= 1
jsonpath "$.data[0].id" == "{{inv_id}}"
jsonpath "$.data[0].status" == "pending"
jsonpath "$.data[0].created_by_account.slug" exists

# Step 4: filter by kind=grant → pending membership invite should NOT appear
GET {{base_url}}/v1/accounts/{{inviter_account_id}}/invitations?kind=grant
Authorization: Bearer {{inviter_token}}

HTTP 200
[Asserts]
jsonpath "$.data[*].id" not contains "{{inv_id}}"

# Step 5: single-invitation GET returns metadata without accept_url
GET {{base_url}}/v1/invitations/{{inv_id}}
Authorization: Bearer {{inviter_token}}

HTTP 200
[Asserts]
jsonpath "$.id" == "{{inv_id}}"
jsonpath "$.status" == "pending"
jsonpath "$.kind" == "membership"
jsonpath "$.accept_url" not exists
jsonpath "$.created_by_account.id" == "{{inviter_account_id}}"

# Step 6: resend the invitation → new accept_url, old token invalidated
POST {{base_url}}/v1/invitations/{{inv_id}}/resend
Authorization: Bearer {{inviter_token}}

HTTP 200
[Asserts]
jsonpath "$.invitation.id" == "{{inv_id}}"
jsonpath "$.accept_url" matches "/invitations/"
jsonpath "$.accept_url" != "{{old_accept_url}}"
[Captures]
new_raw_token: jsonpath "$.accept_url" regex "/invitations/(.+)$"

# Step 7: old raw token no longer resolves (404)
GET {{base_url}}/v1/invitations/{{old_raw_token}}/lookup

HTTP 404

# Step 8: new raw token resolves
GET {{base_url}}/v1/invitations/{{new_raw_token}}/lookup

HTTP 200
[Asserts]
jsonpath "$.kind" == "membership"
jsonpath "$.email" == "e2e-sv2-invitee-1@test.com"

# Step 9: revoke the invitation → 204
DELETE {{base_url}}/v1/invitations/{{inv_id}}
Authorization: Bearer {{inviter_token}}

HTTP 204

# Step 10: subsequent GET returns 404
GET {{base_url}}/v1/invitations/{{inv_id}}
Authorization: Bearer {{inviter_token}}

HTTP 404

# Step 11: new raw token also no longer resolves after revoke
GET {{base_url}}/v1/invitations/{{new_raw_token}}/lookup

HTTP 404

# Step 12: event trail includes created / resent / revoked for this invitation
GET {{base_url}}/v1/events?resource_type=invitation&resource_id={{inv_id}}
Authorization: Bearer {{inviter_token}}

HTTP 200
[Asserts]
jsonpath "$.data[*].event_type" contains "invitation.created"
jsonpath "$.data[*].event_type" contains "invitation.resent"
jsonpath "$.data[*].event_type" contains "invitation.revoked"

# ── Resend-rejection paths ───────────────────────────────────────────

# Step 13: create a second invitation, accept it, then resend → 422 already_accepted
POST {{base_url}}/v1/accounts/{{inviter_account_id}}/invitations
Authorization: Bearer {{inviter_token}}
Content-Type: application/json
{
  "email": "e2e-sv2-invitee-2@test.com",
  "role_slug": "admin"
}

HTTP 201
[Captures]
inv2_id: jsonpath "$.invitation.id"
inv2_raw: jsonpath "$.accept_url" regex "/invitations/(.+)$"

# Step 14: sign up invitee 2 and accept
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Invitee 2 Co",
  "email": "e2e-sv2-invitee-2@test.com",
  "password": "password123"
}

HTTP 201
[Captures]
invitee2_token: jsonpath "$.access_token"

POST {{base_url}}/v1/invitations/{{inv2_raw}}/accept
Authorization: Bearer {{invitee2_token}}

HTTP 200

# Step 15: resend an already-accepted invitation → 422 invitation_already_accepted
POST {{base_url}}/v1/invitations/{{inv2_id}}/resend
Authorization: Bearer {{inviter_token}}

HTTP 422
[Asserts]
jsonpath "$.error.code" == "invitation_already_accepted"

# Step 16: revoke an already-accepted invitation → 422 invitation_already_accepted
DELETE {{base_url}}/v1/invitations/{{inv2_id}}
Authorization: Bearer {{inviter_token}}

HTTP 422
[Asserts]
jsonpath "$.error.code" == "invitation_already_accepted"

# Step 17: revoke a non-existent invitation → 404
DELETE {{base_url}}/v1/invitations/00000000-0000-0000-0000-000000000000
Authorization: Bearer {{inviter_token}}

HTTP 404

# ── Permission gating on list (PR-4.2) ────────────────────────────────
#
# A read_only member must not see the grant-invitation drafts of other
# members in the account — drafts contain capability lists, expected
# emails, and product metadata. The handler restricts grant-kind reads
# to invitations the caller themselves created when the caller lacks
# both grant:issue and grant:use. Of the preset roles, only read_only
# satisfies "lacks both" cleanly: developer also has neither grant
# permission, but operator has grant:use; owner/admin have grant:issue.

# Step 18: inviter creates a product to attach a grant invitation to.
POST {{base_url}}/v1/products
Authorization: Bearer {{inviter_token}}
Content-Type: application/json
{
  "slug": "sv2-gate-product",
  "name": "Sharing v2 Gate Product"
}

HTTP 201
[Captures]
gate_product_id: jsonpath "$.id"

# Step 19: inviter issues a grant-kind invitation. This is the row a
# read_only caller MUST NOT see in the kind=grant listing.
POST {{base_url}}/v1/accounts/{{inviter_account_id}}/invitations
Authorization: Bearer {{inviter_token}}
Content-Type: application/json
{
  "email": "e2e-sv2-grantee@test.com",
  "grant_draft": {
    "product_id": "{{gate_product_id}}",
    "capabilities": ["LICENSE_CREATE", "LICENSE_READ"]
  }
}

HTTP 201
[Captures]
gate_grant_inv_id: jsonpath "$.invitation.id"

# Step 20: inviter invites a read_only member.
POST {{base_url}}/v1/accounts/{{inviter_account_id}}/invitations
Authorization: Bearer {{inviter_token}}
Content-Type: application/json
{
  "email": "e2e-sv2-readonly@test.com",
  "role_slug": "read_only"
}

HTTP 201
[Captures]
ro_invite_token: jsonpath "$.accept_url" regex "/invitations/(.+)$"

# Step 21: read_only invitee signs up to obtain an identity.
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Read Only Personal",
  "email": "e2e-sv2-readonly@test.com",
  "password": "password123"
}

HTTP 201
[Captures]
ro_signup_token: jsonpath "$.access_token"

# Step 22: accept the membership invitation.
POST {{base_url}}/v1/invitations/{{ro_invite_token}}/accept
Authorization: Bearer {{ro_signup_token}}

HTTP 200
[Captures]
ro_membership_id: jsonpath "$.membership_id"

# Step 23: switch to the read_only membership in the inviter's account.
# The reissued JWT carries TargetAccountID = inviter_account_id and
# Role = read_only.
POST {{base_url}}/v1/auth/switch
Authorization: Bearer {{ro_signup_token}}
Content-Type: application/json
{
  "membership_id": "{{ro_membership_id}}"
}

HTTP 200
[Captures]
ro_token: jsonpath "$.access_token"

# Step 24: read_only filters the invitation list by kind=grant. Without
# the gating, the read_only member would see gate_grant_inv_id (a
# draft created by another member). With the gating, read_only is
# narrowed to own-only — and they have created none — so the list is
# empty.
GET {{base_url}}/v1/accounts/{{inviter_account_id}}/invitations?kind=grant
Authorization: Bearer {{ro_token}}

HTTP 200
[Asserts]
jsonpath "$.data" count == 0
jsonpath "$.has_more" == false

# Step 25: read_only filters by kind=membership. read_only carries
# user:list (seeded by migration 030), so the membership-kind side
# remains fully visible.
GET {{base_url}}/v1/accounts/{{inviter_account_id}}/invitations?kind=membership
Authorization: Bearer {{ro_token}}

HTTP 200
[Asserts]
jsonpath "$.data" count >= 1
jsonpath "$.data[*].id" not contains "{{gate_grant_inv_id}}"

# Step 26: no kind filter at all. Mixed-case narrowing kicks in:
# read_only can see all membership but no grant; the handler narrows
# to membership-kind so the response never includes gate_grant_inv_id.
GET {{base_url}}/v1/accounts/{{inviter_account_id}}/invitations
Authorization: Bearer {{ro_token}}

HTTP 200
[Asserts]
jsonpath "$.data[*].id" not contains "{{gate_grant_inv_id}}"

# Step 27: inviter (owner role) hits the same kind=grant query and
# DOES see gate_grant_inv_id — proves the gating is per-caller, not
# a global filter regression.
GET {{base_url}}/v1/accounts/{{inviter_account_id}}/invitations?kind=grant
Authorization: Bearer {{inviter_token}}

HTTP 200
[Asserts]
jsonpath "$.data[*].id" contains "{{gate_grant_inv_id}}"
