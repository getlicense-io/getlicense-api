package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

// bindStrict decodes the request body into dst, REJECTING unknown
// fields with 422 ErrValidationError. Use this on write endpoints
// where the contract is documented in OpenAPI — surfacing unknown
// fields as errors catches client typos early and prevents silent
// drift between client and server.
//
// In addition to unknown-field rejection, bindStrict also rejects
// trailing JSON content after the first document (e.g. a request
// body of `{"a":1} {"b":2}`). encoding/json's decoder reads the
// first object cleanly and would otherwise ignore the rest, which
// silently drops attacker-controlled data.
//
// After decoding, bindStrict runs the app's StructValidator (the
// go-playground/validator wired in NewApp) so `validate:"required"`,
// `validate:"min=1"`, and similar tags are honored — matching the
// behavior of c.Bind().Body() that this helper replaces. Without
// this, struct tags on request types would silently no-op under
// strict bind, allowing empty-array bulk requests, missing required
// fields, etc. to bypass server-side validation.
//
// Repo rule: JSON write handlers use bindStrict. Direct Fiber body
// binding is blocked by scripts/check-bind-strict.sh in CI.
func bindStrict(c fiber.Ctx, dst any) error {
	body := c.Body()
	if len(body) == 0 {
		return core.NewAppError(core.ErrValidationError, "Request body is required")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return core.NewAppError(core.ErrValidationError,
			"Invalid request body: "+humanizeJSONError(err))
	}
	// Reject trailing JSON (e.g. {"a":1} {"b":2}) — DisallowUnknownFields
	// alone doesn't catch this because the first object decodes cleanly.
	// json.Decoder.Decode tokenizes through trailing whitespace and only
	// returns io.EOF if no more tokens follow. Anything else (a value, a
	// type error, or trailing junk) means the client sent more than one
	// document; reject it as a strict-bind violation.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return core.NewAppError(core.ErrValidationError,
			"Invalid request body: trailing JSON content after document")
	}
	// Run the app's StructValidator on dst so `validate:"..."` tags fire
	// the same way they do for c.Bind().Body(). The struct validator
	// shipped in NewApp wraps go-playground/validator and rewraps
	// failures as ErrValidationError; if no validator is configured
	// (e.g. tests), this is a no-op.
	if v := c.App().Config().StructValidator; v != nil {
		if err := v.Validate(dst); err != nil {
			return err
		}
	}
	return nil
}

// humanizeJSONError unwraps the typical encoding/json errors into
// messages the client API surface can display. The raw errors expose
// internal Go field names; this helper rewrites them into something
// closer to the JSON property names callers actually sent.
func humanizeJSONError(err error) string {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return "field " + typeErr.Field + " has wrong type (expected " + typeErr.Type.String() + ")"
	}
	msg := err.Error()
	// Decode error messages from json.DisallowUnknownFields look like:
	//   "json: unknown field \"foo\""
	if strings.HasPrefix(msg, "json: unknown field ") {
		return "unknown field " + strings.TrimPrefix(msg, "json: unknown field ")
	}
	return msg
}
