package handler

import (
	"bytes"
	"encoding/json"
	"errors"
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
// Convention: prefer bindStrict over c.Bind().Body() for new
// handlers. Migration of older handlers is incremental — each one
// becomes strict in a separate change to limit blast radius.
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
