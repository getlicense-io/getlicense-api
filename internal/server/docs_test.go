package server

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
)

// buildDocsTestApp creates a minimal Fiber app with only registerDocs
// mounted. It deliberately skips NewApp because that requires a full
// Deps (DB pool, crypto keys, etc.); we only need the docs middleware
// under test.
func buildDocsTestApp(t *testing.T) *fiber.App {
	t.Helper()
	app := fiber.New()
	registerDocs(app)
	return app
}

func TestDocsServesSwaggerUI(t *testing.T) {
	app := buildDocsTestApp(t)
	req := httptest.NewRequest("GET", "/docs", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Fatalf("GET /docs: expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Fatalf("GET /docs: expected text/html Content-Type, got %q", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}
	// Canonical Swagger UI bundle marker. If the middleware ever
	// rebrands this string, update the assertion — the intent is
	// "the Swagger UI loaded", not a brittle exact match.
	if !strings.Contains(string(body), "swagger-ui") {
		snippet := body
		if len(snippet) > 500 {
			snippet = snippet[:500]
		}
		t.Fatalf("GET /docs body missing 'swagger-ui' marker; got: %s", snippet)
	}
}
