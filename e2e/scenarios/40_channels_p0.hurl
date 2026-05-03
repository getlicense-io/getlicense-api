# 40_channels_p0.hurl — Channels P0: list + get + Grant.channel embed
#
# Covers:
#   - GET /v1/accounts/:id/channels lists auto-created channels
#   - GET /v1/accounts/:id/channels/:cid returns single channel with embeds
#   - GET /v1/channels/:cid (caller-scoped) works for vendor and partner
#   - Grant.channel embed populated on /v1/grants reads
#   - Stranger GET /v1/channels/:cid returns 404 (no existence leak)
#   - Filter by status and partner_account_id

# Step 1: vendor signup
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Channels Vendor",
  "email": "e2e-channels-vendor@test.com",
  "password": "password123"
}

HTTP 201
[Captures]
vendor_token: jsonpath "$.access_token"
vendor_account_id: jsonpath "$.account.id"

# Step 2: vendor creates a product
POST {{base_url}}/v1/products
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "name": "Channels P0 Widget",
  "slug": "channels-p0-widget"
}

HTTP 201
[Captures]
product_id: jsonpath "$.id"

# Step 3: partner signup
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Channels Partner",
  "email": "e2e-channels-partner@test.com",
  "password": "password123"
}

HTTP 201
[Captures]
partner_token: jsonpath "$.access_token"
partner_account_id: jsonpath "$.account.id"
partner_account_slug: jsonpath "$.account.slug"

# Step 4: vendor issues a grant to partner. The inline-channel side
# effect (T11b) auto-creates a single-product channel named
# "{partner.name} — {product.name}" and parents the grant under it.
# The create response returns the raw grant struct (no JOIN re-read),
# so $.channel is NOT present here. channel_id is captured below via
# the list-channels step.
POST {{base_url}}/v1/accounts/{{vendor_account_id}}/grants
Authorization: Bearer {{vendor_token}}
Content-Type: application/json
{
  "grantee_account_id": "{{partner_account_id}}",
  "product_id": "{{product_id}}",
  "capabilities": ["LICENSE_CREATE", "LICENSE_READ"]
}

HTTP 201
[Captures]
grant_id: jsonpath "$.id"
[Asserts]
jsonpath "$.id" exists
jsonpath "$.status" == "pending"

# Step 5: partner accepts the grant
POST {{base_url}}/v1/grants/{{grant_id}}/accept
Authorization: Bearer {{partner_token}}

HTTP 200

# Step 6: vendor lists channels — should see the auto-created one.
# channel_id is captured here because the Issue path does not re-read
# the grant (no JOIN), so the channel embed is absent on the create
# response.
GET {{base_url}}/v1/accounts/{{vendor_account_id}}/channels
Authorization: Bearer {{vendor_token}}

HTTP 200
[Asserts]
jsonpath "$.data" count >= 1
jsonpath "$.data[0].id" exists
jsonpath "$.data[0].vendor_account.id" == "{{vendor_account_id}}"
jsonpath "$.data[0].name" exists
jsonpath "$.data[0].status" exists
[Captures]
channel_id: jsonpath "$.data[0].id"
channel_name: jsonpath "$.data[0].name"

# Step 7: vendor GETs single channel by id (account-scoped path)
GET {{base_url}}/v1/accounts/{{vendor_account_id}}/channels/{{channel_id}}
Authorization: Bearer {{vendor_token}}

HTTP 200
[Asserts]
jsonpath "$.id" == "{{channel_id}}"
jsonpath "$.vendor_account.id" == "{{vendor_account_id}}"
jsonpath "$.partner_account.id" == "{{partner_account_id}}"
jsonpath "$.partner_account.slug" == "{{partner_account_slug}}"

# Step 8: caller-scoped GET works for the vendor
GET {{base_url}}/v1/channels/{{channel_id}}
Authorization: Bearer {{vendor_token}}

HTTP 200
[Asserts]
jsonpath "$.id" == "{{channel_id}}"

# Step 9: caller-scoped GET works for the partner
GET {{base_url}}/v1/channels/{{channel_id}}
Authorization: Bearer {{partner_token}}

HTTP 200
[Asserts]
jsonpath "$.id" == "{{channel_id}}"
jsonpath "$.partner_account.id" == "{{partner_account_id}}"

# Step 10: an unrelated account cannot read the channel (no existence leak)
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Channels Stranger",
  "email": "e2e-channels-stranger@test.com",
  "password": "password123"
}

HTTP 201
[Captures]
stranger_token: jsonpath "$.access_token"

GET {{base_url}}/v1/channels/{{channel_id}}
Authorization: Bearer {{stranger_token}}

HTTP 404

# Step 11: vendor lists grants — verify Grant.channel embed populated by
# the grantor list path (which uses a JOIN query that includes channel_name)
GET {{base_url}}/v1/accounts/{{vendor_account_id}}/grants
Authorization: Bearer {{vendor_token}}

HTTP 200
[Asserts]
jsonpath "$.data[0].channel.id" == "{{channel_id}}"
jsonpath "$.data[0].channel.name" == "{{channel_name}}"

# Step 12: filter list by status (pending — auto-created channels start
# as pending; Accept transitions the grant but does not cascade the
# channel status in P0)
GET {{base_url}}/v1/accounts/{{vendor_account_id}}/channels?status=pending
Authorization: Bearer {{vendor_token}}

HTTP 200
[Asserts]
jsonpath "$.data" count >= 1

# Step 13: filter list by partner_account_id
GET {{base_url}}/v1/accounts/{{vendor_account_id}}/channels?partner_account_id={{partner_account_id}}
Authorization: Bearer {{vendor_token}}

HTTP 200
[Asserts]
jsonpath "$.data" count >= 1
jsonpath "$.data[0].partner_account.id" == "{{partner_account_id}}"
