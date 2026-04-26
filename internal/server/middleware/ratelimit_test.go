package middleware_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// errorHandler mirrors the production server's translation of AppError
// into a JSON envelope with the typed code. Tests need this so the
// 429 + body assertions reflect what real callers see.
func errorHandler(c fiber.Ctx, err error) error {
	var ae *core.AppError
	if errors.As(err, &ae) {
		return c.Status(ae.HTTPStatus()).JSON(fiber.Map{
			"error": fiber.Map{"code": string(ae.Code), "message": ae.Message},
		})
	}
	return c.Status(500).JSON(fiber.Map{"error": err.Error()})
}

func newApp() *fiber.App {
	return fiber.New(fiber.Config{ErrorHandler: errorHandler})
}

func okHandler(c fiber.Ctx) error { return c.SendString("ok") }

func postJSON(t *testing.T, app *fiber.App, path, body string) *httptestResponse {
	t.Helper()
	req := httptest.NewRequest("POST", path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	out := &httptestResponse{StatusCode: resp.StatusCode, Header: resp.Header.Clone()}
	out.Body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return out
}

type httptestResponse struct {
	StatusCode int
	Header     map[string][]string
	Body       []byte
}

func (r *httptestResponse) BodyString() string { return string(r.Body) }

func TestLoginRateLimitPerEmail_BlocksAfter5Attempts(t *testing.T) {
	app := newApp()
	app.Post("/test", middleware.LoginRateLimitPerEmail(), okHandler)

	body := `{"email":"alice@example.com","password":"x"}`
	for i := 1; i <= 5; i++ {
		resp := postJSON(t, app, "/test", body)
		assert.Equal(t, 200, resp.StatusCode, "attempt %d should pass", i)
	}
	resp := postJSON(t, app, "/test", body)
	assert.Equal(t, 429, resp.StatusCode)
	assert.Contains(t, resp.BodyString(), "rate_limit_exceeded")
	assert.Equal(t, "900", resp.Header["Retry-After"][0])
}

func TestLoginRateLimitPerEmail_DifferentEmailsIsolated(t *testing.T) {
	app := newApp()
	app.Post("/test", middleware.LoginRateLimitPerEmail(), okHandler)

	for i := 1; i <= 5; i++ {
		resp := postJSON(t, app, "/test", `{"email":"a@example.com","password":"x"}`)
		require.Equal(t, 200, resp.StatusCode)
	}
	for i := 1; i <= 5; i++ {
		resp := postJSON(t, app, "/test", `{"email":"b@example.com","password":"x"}`)
		require.Equal(t, 200, resp.StatusCode, "B attempt %d should not be locked by A's bucket", i)
	}
}

func TestLoginRateLimitPerEmail_CaseAndWhitespaceNormalized(t *testing.T) {
	app := newApp()
	app.Post("/test", middleware.LoginRateLimitPerEmail(), okHandler)

	bodies := []string{
		`{"email":"Alice@Example.com","password":"x"}`,
		`{"email":"alice@example.com","password":"x"}`,
		`{"email":"  ALICE@example.com  ","password":"x"}`,
		`{"email":"alice@EXAMPLE.com","password":"x"}`,
		`{"email":" alice@example.com","password":"x"}`,
	}
	for i, b := range bodies {
		resp := postJSON(t, app, "/test", b)
		require.Equal(t, 200, resp.StatusCode, "attempt %d (%s) should pass", i+1, b)
	}
	// 6th — they all share a normalized bucket post-trim+lower.
	resp := postJSON(t, app, "/test", `{"email":"alice@example.com","password":"x"}`)
	assert.Equal(t, 429, resp.StatusCode)
	assert.Contains(t, resp.BodyString(), "rate_limit_exceeded")
}

func TestLoginRateLimitPerIP_BlocksAfterMaxAttempts(t *testing.T) {
	app := newApp()
	app.Post("/test", middleware.LoginRateLimitPerIP(60), okHandler)

	for i := 1; i <= 60; i++ {
		// Vary the email so the per-email bucket (if it were chained)
		// could not be the cause; here we only test the IP bucket.
		body := fmt.Sprintf(`{"email":"u%d@example.com","password":"x"}`, i)
		resp := postJSON(t, app, "/test", body)
		require.Equal(t, 200, resp.StatusCode, "attempt %d should pass", i)
	}
	resp := postJSON(t, app, "/test", `{"email":"overflow@example.com","password":"x"}`)
	assert.Equal(t, 429, resp.StatusCode)
	assert.Contains(t, resp.BodyString(), "rate_limit_exceeded")
	assert.Equal(t, "60", resp.Header["Retry-After"][0])
}

func TestLoginTOTPRateLimitPerToken_BlocksAfter5Attempts(t *testing.T) {
	app := newApp()
	app.Post("/test", middleware.LoginTOTPRateLimitPerToken(), okHandler)

	body := `{"pending_token":"pt_abc123","code":"000000"}`
	for i := 1; i <= 5; i++ {
		resp := postJSON(t, app, "/test", body)
		require.Equal(t, 200, resp.StatusCode, "attempt %d should pass", i)
	}
	resp := postJSON(t, app, "/test", body)
	assert.Equal(t, 429, resp.StatusCode)
	assert.Contains(t, resp.BodyString(), "rate_limit_exceeded")
	assert.Equal(t, "900", resp.Header["Retry-After"][0])
}

func TestLoginTOTPRateLimitPerToken_DifferentTokensIsolated(t *testing.T) {
	app := newApp()
	app.Post("/test", middleware.LoginTOTPRateLimitPerToken(), okHandler)

	for i := 1; i <= 5; i++ {
		resp := postJSON(t, app, "/test", `{"pending_token":"pt_aaa","code":"000000"}`)
		require.Equal(t, 200, resp.StatusCode)
	}
	for i := 1; i <= 5; i++ {
		resp := postJSON(t, app, "/test", `{"pending_token":"pt_bbb","code":"000000"}`)
		require.Equal(t, 200, resp.StatusCode, "B attempt %d should not be locked by A's bucket", i)
	}
}

func TestRefreshRateLimitPerIP_BlocksAfterMaxAttempts(t *testing.T) {
	app := newApp()
	app.Post("/test", middleware.RefreshRateLimitPerIP(5), okHandler)

	body := `{"refresh_token":"rt_x"}`
	for i := 1; i <= 5; i++ {
		resp := postJSON(t, app, "/test", body)
		require.Equal(t, 200, resp.StatusCode, "attempt %d should pass", i)
	}
	resp := postJSON(t, app, "/test", body)
	assert.Equal(t, 429, resp.StatusCode)
	assert.Contains(t, resp.BodyString(), "rate_limit_exceeded")
	assert.Equal(t, "60", resp.Header["Retry-After"][0])
}

func TestLogoutRateLimitPerIP_BlocksAfterMaxAttempts(t *testing.T) {
	app := newApp()
	app.Post("/test", middleware.LogoutRateLimitPerIP(5), okHandler)

	body := `{"refresh_token":"rt_x"}`
	for i := 1; i <= 5; i++ {
		resp := postJSON(t, app, "/test", body)
		require.Equal(t, 200, resp.StatusCode, "attempt %d should pass", i)
	}
	resp := postJSON(t, app, "/test", body)
	assert.Equal(t, 429, resp.StatusCode)
	assert.Equal(t, "60", resp.Header["Retry-After"][0])
}

func TestLoginTOTPRateLimitPerIP_BlocksAfterMaxAttempts(t *testing.T) {
	app := newApp()
	app.Post("/test", middleware.LoginTOTPRateLimitPerIP(3), okHandler)

	for i := 1; i <= 3; i++ {
		body := fmt.Sprintf(`{"pending_token":"tok_%d","code":"000000"}`, i)
		resp := postJSON(t, app, "/test", body)
		require.Equal(t, 200, resp.StatusCode)
	}
	resp := postJSON(t, app, "/test", `{"pending_token":"tok_overflow","code":"000000"}`)
	assert.Equal(t, 429, resp.StatusCode)
	assert.Equal(t, "60", resp.Header["Retry-After"][0])
}

func TestStackedLoginLimiters_IPCapTripsFirst(t *testing.T) {
	// Mirror the production wiring: IP first, then per-email. With a
	// tiny IP cap and unique emails, the IP bucket must trip — proving
	// the IP layer fires before the per-email layer runs.
	app := newApp()
	app.Post("/test",
		middleware.LoginRateLimitPerIP(3),
		middleware.LoginRateLimitPerEmail(),
		okHandler)

	for i := 1; i <= 3; i++ {
		body := fmt.Sprintf(`{"email":"u%d@example.com","password":"x"}`, i)
		resp := postJSON(t, app, "/test", body)
		require.Equal(t, 200, resp.StatusCode)
	}
	resp := postJSON(t, app, "/test", `{"email":"u4@example.com","password":"x"}`)
	assert.Equal(t, 429, resp.StatusCode)
	// Retry-After == 60 confirms the IP limiter fired (per-email is 900).
	assert.Equal(t, "60", resp.Header["Retry-After"][0])
}

// peekJSONField is unexported, so we exercise it indirectly by feeding
// edge-case bodies through LoginRateLimitPerEmail and observing which
// bucket key gets used (malformed → shared sentinel; valid → email key).
func TestPeekJSONField_HandlesMalformedBody(t *testing.T) {
	tests := []struct {
		name string
		body string
		// "shared" means malformed — every malformed request bumps the
		// _malformed sentinel bucket. Good enough: observe that two
		// distinct malformed bodies share a bucket (the second of the
		// pair fails after the first has saturated the limit) and that
		// a valid body uses an isolated bucket.
		isMalformed bool
	}{
		{"empty body", "", true},
		{"invalid json", "{not json", true},
		{"missing field", `{"other":"foo"}`, true},
		{"non-string field", `{"email":123}`, true},
		{"valid string", `{"email":"x@y.com"}`, false},
	}

	// Saturate the malformed bucket first by sending 5 distinct
	// malformed bodies. They should ALL share the _malformed key
	// because peekJSONField returns "" for each.
	app := newApp()
	app.Post("/test", middleware.LoginRateLimitPerEmail(), okHandler)
	malformed := []string{"", "{not json", `{"other":"a"}`, `{"email":42}`, `{}`}
	for _, b := range malformed {
		resp := postJSON(t, app, "/test", b)
		require.Equal(t, 200, resp.StatusCode)
	}
	// 6th malformed body of any shape should now 429.
	for _, tc := range tests {
		if !tc.isMalformed {
			continue
		}
		resp := postJSON(t, app, "/test", tc.body)
		assert.Equal(t, 429, resp.StatusCode, "case=%q malformed bodies share a sentinel bucket", tc.name)
	}
	// Valid body uses its own bucket — should still pass.
	resp := postJSON(t, app, "/test", `{"email":"isolated@example.com","password":"x"}`)
	assert.Equal(t, 200, resp.StatusCode, "valid email bucket isolated from _malformed sentinel")
}

func TestRetryAfterHeader_PresentOnAuthRateLimit(t *testing.T) {
	// Spot-check that the Retry-After header survives the ErrorHandler
	// path. The header is set on c BEFORE returning the AppError; Fiber
	// preserves prior c.Set calls when the ErrorHandler writes the body.
	app := newApp()
	app.Post("/test", middleware.LoginRateLimitPerEmail(), okHandler)
	body := `{"email":"hdr@example.com"}`
	for i := 0; i < 5; i++ {
		_ = postJSON(t, app, "/test", body)
	}
	resp := postJSON(t, app, "/test", body)
	require.Equal(t, 429, resp.StatusCode)
	require.NotEmpty(t, resp.Header["Retry-After"], "Retry-After header must be set by authRateLimitReached")
	assert.Equal(t, "900", resp.Header["Retry-After"][0])
	// Sanity: error envelope has the typed code.
	assert.True(t, strings.Contains(resp.BodyString(), "rate_limit_exceeded"))
}
