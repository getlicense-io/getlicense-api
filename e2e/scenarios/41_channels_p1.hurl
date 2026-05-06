# 41_channels_p1.hurl — Channels P1: partner reads + stats + products list
#
# Covers:
#   - GET /v1/channels/received returns channels where caller is partner
#   - GET /v1/accounts/:id/channels/:cid response includes stats payload
#   - GET /v1/channels/:cid/products returns channel-products with projected status

# Step 1: vendor signup
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Channels P1 Vendor",
  "email": "e2e-channels-p1-vendor@test.com",
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
  "name": "P1 Widget",
  "slug": "p1-widget"
}

HTTP 201
[Captures]
product_id: jsonpath "$.id"

# Step 3: partner signup
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Channels P1 Partner",
  "email": "e2e-channels-p1-partner@test.com",
  "password": "password123"
}

HTTP 201
[Captures]
partner_token: jsonpath "$.access_token"
partner_account_id: jsonpath "$.account.id"

# Step 4: vendor issues grant to partner (auto-creates channel inline)
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

# Step 6: vendor lists channels to discover the auto-created one
GET {{base_url}}/v1/accounts/{{vendor_account_id}}/channels
Authorization: Bearer {{vendor_token}}

HTTP 200
[Asserts]
jsonpath "$.data" count >= 1
[Captures]
channel_id: jsonpath "$.data[0].id"

# Step 7: partner GET /v1/channels/received — should see the channel
# (channel stays in pending status because SetPartnerAndActivate is not
# yet wired; ListByPartner returns all statuses so pending is visible)
GET {{base_url}}/v1/channels/received
Authorization: Bearer {{partner_token}}

HTTP 200
[Asserts]
jsonpath "$.data" count >= 1
jsonpath "$.data[0].id" == "{{channel_id}}"
jsonpath "$.data[0].vendor_account.id" == "{{vendor_account_id}}"
jsonpath "$.data[0].partner_account.id" == "{{partner_account_id}}"

# Step 8: vendor GET single channel — verify stats payload present
GET {{base_url}}/v1/accounts/{{vendor_account_id}}/channels/{{channel_id}}
Authorization: Bearer {{vendor_token}}

HTTP 200
[Asserts]
jsonpath "$.id" == "{{channel_id}}"
jsonpath "$.stats" exists
jsonpath "$.stats.products_total" exists
jsonpath "$.stats.products_active" exists
jsonpath "$.stats.licenses_total" exists
jsonpath "$.stats.licenses_this_month" exists
jsonpath "$.stats.customers_total" exists
jsonpath "$.stats.products_total" >= 1
jsonpath "$.stats.products_active" >= 1

# Step 9: partner GET single channel (caller-scoped) — stats payload also present.
# Partner-side licenses_total and customers_total may read 0 due to RLS
# (documented limitation matching Grant.Usage gotcha); assert the stats
# object exists but not numeric lower bounds.
GET {{base_url}}/v1/channels/{{channel_id}}
Authorization: Bearer {{partner_token}}

HTTP 200
[Asserts]
jsonpath "$.id" == "{{channel_id}}"
jsonpath "$.stats" exists
jsonpath "$.stats.products_total" exists

# Step 10: vendor lists channel-products — should see one entry per grant.
# ChannelProduct.id == grants.id (same identity space), status projected
# from grant status: accepted grant → active channel-product.
GET {{base_url}}/v1/accounts/{{vendor_account_id}}/channels/{{channel_id}}/products
Authorization: Bearer {{vendor_token}}

HTTP 200
[Asserts]
jsonpath "$.data" count >= 1
jsonpath "$.data[0].id" == "{{grant_id}}"
jsonpath "$.data[0].channel_id" == "{{channel_id}}"
jsonpath "$.data[0].product.id" == "{{product_id}}"
jsonpath "$.data[0].status" == "active"

# Step 11: partner lists channel-products (caller-scoped) — same result
GET {{base_url}}/v1/channels/{{channel_id}}/products
Authorization: Bearer {{partner_token}}

HTTP 200
[Asserts]
jsonpath "$.data" count >= 1
jsonpath "$.data[0].id" == "{{grant_id}}"
jsonpath "$.data[0].status" == "active"

# Step 12: unrelated account (stranger) cannot list products — 404, no existence leak
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Channels P1 Stranger",
  "email": "e2e-channels-p1-stranger@test.com",
  "password": "password123"
}

HTTP 201
[Captures]
stranger_token: jsonpath "$.access_token"

GET {{base_url}}/v1/channels/{{channel_id}}/products
Authorization: Bearer {{stranger_token}}

HTTP 404
