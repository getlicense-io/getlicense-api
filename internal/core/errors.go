package core

import (
	"encoding/json"
	"fmt"
)

// ErrorCode is a string identifier for an application error.
type ErrorCode string

// Error code constants.
const (
	ErrAuthenticationRequired  ErrorCode = "authentication_required"
	ErrInvalidAPIKey           ErrorCode = "invalid_api_key"
	ErrInsufficientPermissions ErrorCode = "insufficient_permissions"

	ErrAccountNotFound          ErrorCode = "account_not_found"
	ErrProductNotFound          ErrorCode = "product_not_found"
	ErrLicenseNotFound          ErrorCode = "license_not_found"
	ErrMachineNotFound          ErrorCode = "machine_not_found"
	ErrAPIKeyNotFound           ErrorCode = "api_key_not_found"
	ErrWebhookEndpointNotFound  ErrorCode = "webhook_endpoint_not_found"

	ErrAccountAlreadyExists    ErrorCode = "account_already_exists"
	ErrEmailAlreadyExists      ErrorCode = "email_already_exists"
	ErrLicenseAlreadyActive    ErrorCode = "license_already_active"
	ErrMachineAlreadyActivated ErrorCode = "machine_already_activated"

	ErrLicenseExpired      ErrorCode = "license_expired"
	ErrLicenseSuspended    ErrorCode = "license_suspended"
	ErrLicenseRevoked      ErrorCode = "license_revoked"
	ErrLicenseInactive     ErrorCode = "license_inactive"
	ErrMachineLimitExceeded ErrorCode = "machine_limit_exceeded"
	ErrInvalidLicenseKey   ErrorCode = "invalid_license_key"
	ErrInvalidLicenseToken ErrorCode = "invalid_license_token"
	ErrValidationError     ErrorCode = "validation_error"

	ErrRateLimitExceeded ErrorCode = "rate_limit_exceeded"

	ErrInternalError ErrorCode = "internal_error"
)

// httpStatusMap maps each error code to its HTTP status code.
var httpStatusMap = map[ErrorCode]int{
	ErrAuthenticationRequired:  401,
	ErrInvalidAPIKey:           401,
	ErrInsufficientPermissions: 403,

	ErrAccountNotFound:         404,
	ErrProductNotFound:         404,
	ErrLicenseNotFound:         404,
	ErrMachineNotFound:         404,
	ErrAPIKeyNotFound:          404,
	ErrWebhookEndpointNotFound: 404,

	ErrAccountAlreadyExists:    409,
	ErrEmailAlreadyExists:      409,
	ErrLicenseAlreadyActive:    409,
	ErrMachineAlreadyActivated: 409,

	ErrLicenseExpired:      422,
	ErrLicenseSuspended:    422,
	ErrLicenseRevoked:      422,
	ErrLicenseInactive:     422,
	ErrMachineLimitExceeded: 422,
	ErrInvalidLicenseKey:   422,
	ErrInvalidLicenseToken: 422,
	ErrValidationError:     422,

	ErrRateLimitExceeded: 429,

	ErrInternalError: 500,
}

// HTTPStatus returns the HTTP status code associated with this error code.
// Returns 500 if the code is not recognized.
func (c ErrorCode) HTTPStatus() int {
	if status, ok := httpStatusMap[c]; ok {
		return status
	}
	return 500
}

// AppError is a structured application error with a code, message, and documentation URL.
type AppError struct {
	Code    ErrorCode
	Message string
}

// NewAppError creates a new AppError with the given code and message.
func NewAppError(code ErrorCode, message string) *AppError {
	return &AppError{Code: code, Message: message}
}

// Error implements the error interface.
// Includes the error code for debugging: "license_expired: License has expired".
func (e *AppError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// HTTPStatus returns the HTTP status code for this error.
func (e *AppError) HTTPStatus() int {
	return e.Code.HTTPStatus()
}

// MarshalJSON produces the canonical error envelope:
//
//	{"error":{"code":"...","message":"...","doc_url":"https://getlicense.io/docs/errors/..."}}
func (e *AppError) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			DocURL  string `json:"doc_url"`
		} `json:"error"`
	}{
		Error: struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			DocURL  string `json:"doc_url"`
		}{
			Code:    string(e.Code),
			Message: e.Message,
			DocURL:  "https://getlicense.io/docs/errors/" + string(e.Code),
		},
	})
}
