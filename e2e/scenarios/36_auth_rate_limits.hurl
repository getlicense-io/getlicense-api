# 36_auth_rate_limits.hurl — verify login attempts are rate-limited
# per email. Five successive failed logins for the same email get the
# sixth rejected with 429 + Retry-After.
#
# This scenario uses a deliberately-unique email so the per-email
# bucket cannot interfere with other scenarios. The per-IP cap is
# raised in development (deps.Config.IsDevelopment) so the dev e2e
# loop does not trip it; per-email stays tight in every environment.

# --- Signup so the email exists in the system ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "Rate Limit Vendor",
  "email": "e2e-ratelimit@test.com",
  "password": "correctpassword"
}
HTTP 201

# --- 5 failed logins (wrong password, 401) — all should pass the limiter ---
POST {{base_url}}/v1/auth/login
Content-Type: application/json
{ "email": "e2e-ratelimit@test.com", "password": "wrong-1" }
HTTP 401

POST {{base_url}}/v1/auth/login
Content-Type: application/json
{ "email": "e2e-ratelimit@test.com", "password": "wrong-2" }
HTTP 401

POST {{base_url}}/v1/auth/login
Content-Type: application/json
{ "email": "e2e-ratelimit@test.com", "password": "wrong-3" }
HTTP 401

POST {{base_url}}/v1/auth/login
Content-Type: application/json
{ "email": "e2e-ratelimit@test.com", "password": "wrong-4" }
HTTP 401

POST {{base_url}}/v1/auth/login
Content-Type: application/json
{ "email": "e2e-ratelimit@test.com", "password": "wrong-5" }
HTTP 401

# --- 6th attempt → 429 with rate_limit_exceeded + Retry-After ---
POST {{base_url}}/v1/auth/login
Content-Type: application/json
{ "email": "e2e-ratelimit@test.com", "password": "wrong-6" }
HTTP 429
[Asserts]
jsonpath "$.error.code" == "rate_limit_exceeded"
header "Retry-After" == "900"

# --- A different email is NOT locked out (per-email isolation) ---
POST {{base_url}}/v1/auth/login
Content-Type: application/json
{ "email": "e2e-ratelimit-other@test.com", "password": "irrelevant" }
HTTP 401
