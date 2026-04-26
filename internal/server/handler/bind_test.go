package handler

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

type bindTestReq struct {
	Label string `json:"label"`
}

// newAppForBindTest builds a Fiber app with the standard test
// ErrorHandler — unwraps *core.AppError to its HTTP status + JSON
// body so the test can assert on the typed error code.
func newAppForBindTest() *fiber.App {
	return fiber.New(fiber.Config{
		ErrorHandler: func(c fiber.Ctx, err error) error {
			var ae *core.AppError
			if errors.As(err, &ae) {
				return c.Status(ae.HTTPStatus()).JSON(ae)
			}
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		},
	})
}

func TestBindStrict_HappyPath(t *testing.T) {
	app := newAppForBindTest()
	var got bindTestReq
	app.Post("/", func(c fiber.Ctx) error {
		if err := bindStrict(c, &got); err != nil {
			return err
		}
		return c.SendString("ok")
	})
	req := newJSONRequest(t, "/", `{"label":"hello"}`)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "hello", got.Label)
}

func TestBindStrict_UnknownFieldRejected(t *testing.T) {
	app := newAppForBindTest()
	var got bindTestReq
	app.Post("/", func(c fiber.Ctx) error {
		if err := bindStrict(c, &got); err != nil {
			return err
		}
		return c.SendString("ok")
	})
	req := newJSONRequest(t, "/", `{"label":"hello","extra":"surprise"}`)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, 422, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "validation_error")
	assert.Contains(t, string(body), "extra")
}

func TestBindStrict_EmptyBodyRejected(t *testing.T) {
	app := newAppForBindTest()
	var got bindTestReq
	app.Post("/", func(c fiber.Ctx) error {
		if err := bindStrict(c, &got); err != nil {
			return err
		}
		return c.SendString("ok")
	})
	req := newJSONRequest(t, "/", "")
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, 422, resp.StatusCode)
}

func TestBindStrict_TypeMismatch(t *testing.T) {
	app := newAppForBindTest()
	var got bindTestReq
	app.Post("/", func(c fiber.Ctx) error {
		if err := bindStrict(c, &got); err != nil {
			return err
		}
		return c.SendString("ok")
	})
	req := newJSONRequest(t, "/", `{"label":42}`) // label is a string, not a number
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, 422, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "wrong type")
}

// TestBindStrict_RejectsTrailingJSON verifies bindStrict catches the
// case where the client sends more than one JSON document in a single
// request body. encoding/json's DisallowUnknownFields alone misses
// this — the first object decodes cleanly and the trailing data is
// silently dropped. bindStrict performs a second Decode call that
// MUST return io.EOF, otherwise we have trailing content.
func TestBindStrict_RejectsTrailingJSON(t *testing.T) {
	app := newAppForBindTest()
	var got bindTestReq
	app.Post("/", func(c fiber.Ctx) error {
		if err := bindStrict(c, &got); err != nil {
			return err
		}
		return c.SendString("ok")
	})
	req := newJSONRequest(t, "/", `{"label":"first"} {"label":"second"}`)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, 422, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "trailing JSON")
}

// TestBindStrict_AllowsWhitespaceAfterDocument confirms that the
// trailing-JSON guard does NOT trip on benign whitespace at end of
// body — a `\n` at EOF is the norm for any JSON payload formatted by
// `jq` or similar. encoding/json's tokenizer skips through whitespace
// when looking for the next token, so the second Decode returns
// io.EOF cleanly and the request is accepted.
func TestBindStrict_AllowsWhitespaceAfterDocument(t *testing.T) {
	app := newAppForBindTest()
	var got bindTestReq
	app.Post("/", func(c fiber.Ctx) error {
		if err := bindStrict(c, &got); err != nil {
			return err
		}
		return c.SendString("ok")
	})
	req := newJSONRequest(t, "/", "{\"label\":\"hi\"}\n  \t\n")
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "hi", got.Label)
}

// newJSONRequest is a small helper that builds an *http.Request with
// the JSON content type and an in-memory body.
func newJSONRequest(t *testing.T, path string, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}
