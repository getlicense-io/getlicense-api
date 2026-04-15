# 16_totp.hurl — TOTP enrollment coverage
# Valid-code paths (activate with good code, verify, disable) are
# covered by unit tests in internal/identity/service_test.go because
# hurl has no way to compute a TOTP code.

POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "TOTP Test Co",
  "email": "e2e-totp@test.com",
  "password": "password123"
}

HTTP 201
[Captures]
access_token: jsonpath "$.access_token"

# Enroll — returns secret + otpauth URL without activating
POST {{base_url}}/v1/identity/totp/enroll
Authorization: Bearer {{access_token}}

HTTP 200
[Asserts]
jsonpath "$.secret" exists
jsonpath "$.otpauth_url" matches "^otpauth://totp/"

# Activate with a wrong code → 401 totp_invalid
POST {{base_url}}/v1/identity/totp/activate
Authorization: Bearer {{access_token}}
Content-Type: application/json
{
  "code": "000000"
}

HTTP 401
[Asserts]
jsonpath "$.error.code" == "totp_invalid"

# POST /auth/login/totp with a bogus pending token → 401
POST {{base_url}}/v1/auth/login/totp
Content-Type: application/json
{
  "pending_token": "fake-token-that-does-not-exist",
  "code": "123456"
}

HTTP 401
[Asserts]
jsonpath "$.error.code" == "authentication_required"
