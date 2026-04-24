package core

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorCodeHTTPStatus(t *testing.T) {
	tests := []struct {
		code     ErrorCode
		expected int
	}{
		{ErrAuthenticationRequired, 401},
		{ErrInvalidAPIKey, 401},
		{ErrInsufficientPermissions, 403},
		{ErrAccountNotFound, 404},
		{ErrProductNotFound, 404},
		{ErrLicenseNotFound, 404},
		{ErrMachineNotFound, 404},
		{ErrAccountAlreadyExists, 409},
		{ErrEmailAlreadyExists, 409},
		{ErrLicenseAlreadyActive, 409},
		{ErrMachineAlreadyActivated, 409},
		{ErrLicenseExpired, 422},
		{ErrLicenseSuspended, 422},
		{ErrLicenseRevoked, 422},
		{ErrLicenseInactive, 422},
		{ErrMachineLimitExceeded, 422},
		{ErrInvalidLicenseKey, 422},
		{ErrInvalidLicenseToken, 422},
		{ErrValidationError, 422},
		{ErrRateLimitExceeded, 429},

		{ErrIdentityNotFound, 404},
		{ErrMembershipNotFound, 404},
		{ErrRoleNotFound, 404},
		{ErrInvitationNotFound, 404},
		{ErrGrantNotFound, 404},

		{ErrInvitationExpired, 410},
		{ErrInvitationAlreadyUsed, 409},

		{ErrGrantNotActive, 422},
		{ErrGrantCapabilityDenied, 403},
		{ErrGrantConstraintViolated, 422},

		{ErrTOTPRequired, 401},
		{ErrTOTPInvalid, 401},
		{ErrTOTPAlreadyEnabled, 409},

		{ErrLastOwner, 422},
		{ErrPermissionDenied, 403},

		{ErrGrantAlreadyLeft, 422},
		{ErrGrantNotEditable, 422},
		{ErrGrantNotSuspended, 422},
		{ErrGrantLabelTooLong, 422},
		{ErrGrantMetadataTooLarge, 422},
		{ErrInvitationAlreadyAccepted, 422},

		{ErrInternalError, 500},
	}

	for _, tt := range tests {
		t.Run(string(tt.code), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.code.HTTPStatus())
		})
	}
}

func TestAppErrorImplementsError(t *testing.T) {
	var e error = &AppError{Code: ErrInternalError, Message: "something went wrong"}
	assert.NotNil(t, e)
	assert.Equal(t, "internal_error: something went wrong", e.Error())
}

func TestNewAppError(t *testing.T) {
	err := NewAppError(ErrLicenseExpired, "license has expired")
	assert.Equal(t, ErrLicenseExpired, err.Code)
	assert.Equal(t, "license has expired", err.Message)
	assert.Equal(t, 422, err.HTTPStatus())
	assert.Equal(t, "license_expired: license has expired", err.Error())
}

func TestAppErrorJSONMarshal(t *testing.T) {
	appErr := &AppError{
		Code:    ErrLicenseNotFound,
		Message: "license not found",
	}

	b, err := json.Marshal(appErr)
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(b, &out))

	errObj, ok := out["error"].(map[string]any)
	require.True(t, ok, "expected top-level 'error' key")

	assert.Equal(t, "license_not_found", errObj["code"])
	assert.Equal(t, "license not found", errObj["message"])
	assert.Equal(t, "https://getlicense.io/docs/errors/license_not_found", errObj["doc_url"])
}

func TestAppErrorJSONMarshalAllCodes(t *testing.T) {
	codes := []ErrorCode{
		ErrAuthenticationRequired, ErrInvalidAPIKey, ErrInsufficientPermissions,
		ErrAccountNotFound, ErrProductNotFound, ErrLicenseNotFound, ErrMachineNotFound,
		ErrAccountAlreadyExists, ErrEmailAlreadyExists, ErrLicenseAlreadyActive, ErrMachineAlreadyActivated,
		ErrLicenseExpired, ErrLicenseSuspended, ErrLicenseRevoked, ErrLicenseInactive,
		ErrMachineLimitExceeded, ErrInvalidLicenseKey, ErrInvalidLicenseToken, ErrValidationError,
		ErrRateLimitExceeded,
		ErrIdentityNotFound, ErrMembershipNotFound, ErrRoleNotFound, ErrInvitationNotFound, ErrGrantNotFound,
		ErrInvitationExpired, ErrInvitationAlreadyUsed,
		ErrGrantNotActive, ErrGrantCapabilityDenied, ErrGrantConstraintViolated,
		ErrTOTPRequired, ErrTOTPInvalid, ErrTOTPAlreadyEnabled,
		ErrLastOwner, ErrPermissionDenied,
		ErrGrantAlreadyLeft, ErrGrantNotEditable, ErrGrantNotSuspended,
		ErrGrantLabelTooLong, ErrGrantMetadataTooLarge, ErrInvitationAlreadyAccepted,
		ErrInternalError,
	}

	for _, code := range codes {
		t.Run(string(code), func(t *testing.T) {
			appErr := &AppError{Code: code, Message: "test"}
			b, err := json.Marshal(appErr)
			require.NoError(t, err)

			var out map[string]any
			require.NoError(t, json.Unmarshal(b, &out))

			errObj, ok := out["error"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, string(code), errObj["code"])
			assert.Equal(t, "https://getlicense.io/docs/errors/"+string(code), errObj["doc_url"])
		})
	}
}

func TestAppErrorAsErrorType(t *testing.T) {
	appErr := &AppError{Code: ErrValidationError, Message: "invalid input"}
	var target *AppError
	assert.True(t, errors.As(appErr, &target))
	assert.Equal(t, ErrValidationError, target.Code)
}
