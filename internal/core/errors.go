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

	ErrAccountNotFound         ErrorCode = "account_not_found"
	ErrProductNotFound         ErrorCode = "product_not_found"
	ErrLicenseNotFound         ErrorCode = "license_not_found"
	ErrMachineNotFound         ErrorCode = "machine_not_found"
	ErrAPIKeyNotFound          ErrorCode = "api_key_not_found"
	ErrWebhookEndpointNotFound ErrorCode = "webhook_endpoint_not_found"
	ErrEnvironmentNotFound     ErrorCode = "environment_not_found"

	ErrAccountAlreadyExists     ErrorCode = "account_already_exists"
	ErrEmailAlreadyExists       ErrorCode = "email_already_exists"
	ErrProductAlreadyExists     ErrorCode = "product_already_exists"
	ErrLicenseAlreadyActive     ErrorCode = "license_already_active"
	ErrMachineAlreadyActivated  ErrorCode = "machine_already_activated"
	ErrEnvironmentAlreadyExists ErrorCode = "environment_already_exists"
	ErrEnvironmentLimitReached  ErrorCode = "environment_limit_reached"
	ErrEnvironmentNotEmpty      ErrorCode = "environment_not_empty"
	ErrLastEnvironment          ErrorCode = "last_environment"

	ErrLicenseExpired           ErrorCode = "license_expired"
	ErrLicenseSuspended         ErrorCode = "license_suspended"
	ErrLicenseRevoked           ErrorCode = "license_revoked"
	ErrLicenseInactive          ErrorCode = "license_inactive"
	ErrLicenseInvalidTransition ErrorCode = "license_invalid_transition"
	ErrMachineLimitExceeded     ErrorCode = "machine_limit_exceeded"
	ErrInvalidLicenseKey        ErrorCode = "invalid_license_key"
	ErrInvalidLicenseToken      ErrorCode = "invalid_license_token"
	ErrValidationError          ErrorCode = "validation_error"
	ErrRequestTooLarge          ErrorCode = "request_too_large"

	ErrRateLimitExceeded ErrorCode = "rate_limit_exceeded"

	ErrIdentityNotFound        ErrorCode = "identity_not_found"
	ErrMembershipNotFound      ErrorCode = "membership_not_found"
	ErrRoleNotFound            ErrorCode = "role_not_found"
	ErrInvitationNotFound      ErrorCode = "invitation_not_found"
	ErrInvitationExpired       ErrorCode = "invitation_expired"
	ErrInvitationAlreadyUsed   ErrorCode = "invitation_already_used"
	ErrGrantNotFound           ErrorCode = "grant_not_found"
	ErrGrantNotActive          ErrorCode = "grant_not_active"
	ErrGrantCapabilityDenied   ErrorCode = "grant_capability_denied"
	ErrGrantConstraintViolated ErrorCode = "grant_constraint_violated"
	ErrTOTPRequired            ErrorCode = "totp_required"
	ErrTOTPInvalid             ErrorCode = "totp_invalid"
	ErrTOTPAlreadyEnabled      ErrorCode = "totp_already_enabled"
	ErrLastOwner               ErrorCode = "last_owner"
	ErrPermissionDenied        ErrorCode = "permission_denied"

	ErrGrantPolicyNotAllowed  ErrorCode = "grant_policy_not_allowed"
	ErrGrantCapabilityMissing ErrorCode = "grant_capability_missing"
	ErrLicenseOverrideInvalid ErrorCode = "license_override_invalid"

	// L2 lease/checkout errors
	ErrMachineDead               ErrorCode = "machine_dead"
	ErrMachineInvalidFingerprint ErrorCode = "machine_invalid_fingerprint"
	ErrLeaseSignFailed           ErrorCode = "lease_sign_failed"

	// Domain event errors (O2)
	ErrEventNotFound ErrorCode = "event_not_found"

	// Webhook delivery errors (O3)
	ErrWebhookEventNotFound     ErrorCode = "webhook_event_not_found"
	ErrDeliveryPredatesEventLog ErrorCode = "delivery_predates_event_log"

	// Entitlement errors (L3)
	ErrEntitlementNotFound        ErrorCode = "entitlement_not_found"
	ErrEntitlementInvalidCode     ErrorCode = "entitlement_invalid_code"
	ErrEntitlementDuplicateCode   ErrorCode = "entitlement_duplicate_code"
	ErrEntitlementInUse           ErrorCode = "entitlement_in_use"
	ErrEntitlementCodeImmutable   ErrorCode = "entitlement_code_immutable"
	ErrGrantEntitlementNotAllowed ErrorCode = "grant_entitlement_not_allowed"

	// Customer errors (L4)
	ErrCustomerNotFound        ErrorCode = "customer_not_found"
	ErrCustomerAmbiguous       ErrorCode = "customer_ambiguous"
	ErrCustomerRequired        ErrorCode = "customer_required"
	ErrCustomerInvalidEmail    ErrorCode = "customer_invalid_email"
	ErrCustomerInUse           ErrorCode = "customer_in_use"
	ErrCustomerAccountMismatch ErrorCode = "customer_account_mismatch"
	ErrPolicyInUse             ErrorCode = "policy_in_use"
	ErrPolicyInvalidBasis      ErrorCode = "policy_invalid_basis"
	ErrPolicyInvalidDuration   ErrorCode = "policy_invalid_duration"
	ErrPolicyInvalidStrategy   ErrorCode = "policy_invalid_strategy"
	ErrPolicyIsDefault         ErrorCode = "policy_is_default"
	ErrPolicyNotFound          ErrorCode = "policy_not_found"
	ErrPolicyProductMismatch   ErrorCode = "policy_product_mismatch"

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
	ErrEnvironmentNotFound:     404,

	ErrAccountAlreadyExists:     409,
	ErrEmailAlreadyExists:       409,
	ErrProductAlreadyExists:     409,
	ErrLicenseAlreadyActive:     409,
	ErrMachineAlreadyActivated:  409,
	ErrEnvironmentAlreadyExists: 409,
	ErrEnvironmentLimitReached:  422,
	ErrEnvironmentNotEmpty:      422,
	ErrLastEnvironment:          422,

	ErrLicenseExpired:           422,
	ErrLicenseSuspended:         422,
	ErrLicenseRevoked:           422,
	ErrLicenseInactive:          422,
	ErrLicenseInvalidTransition: 422,
	ErrMachineLimitExceeded:     422,
	ErrInvalidLicenseKey:        422,
	ErrInvalidLicenseToken:      422,
	ErrValidationError:          422,
	ErrRequestTooLarge:          413,

	ErrRateLimitExceeded: 429,

	ErrIdentityNotFound:   404,
	ErrMembershipNotFound: 404,
	ErrRoleNotFound:       404,
	ErrInvitationNotFound: 404,
	ErrGrantNotFound:      404,

	ErrInvitationExpired:     410,
	ErrInvitationAlreadyUsed: 409,

	ErrGrantNotActive:          422,
	ErrGrantCapabilityDenied:   403,
	ErrGrantConstraintViolated: 422,

	ErrTOTPRequired:       401,
	ErrTOTPInvalid:        401,
	ErrTOTPAlreadyEnabled: 409,

	ErrLastOwner:        422,
	ErrPermissionDenied: 403,

	ErrPolicyNotFound:         404,
	ErrPolicyInvalidDuration:  422,
	ErrPolicyInvalidStrategy:  422,
	ErrPolicyInvalidBasis:     422,
	ErrPolicyIsDefault:        422,
	ErrPolicyInUse:            422,
	ErrPolicyProductMismatch:  422,
	ErrLicenseOverrideInvalid: 422,
	ErrGrantPolicyNotAllowed:  403,
	ErrGrantCapabilityMissing: 403,

	ErrCustomerNotFound:        404,
	ErrCustomerAmbiguous:       422,
	ErrCustomerRequired:        422,
	ErrCustomerInvalidEmail:    422,
	ErrCustomerInUse:           409,
	ErrCustomerAccountMismatch: 422,

	ErrMachineDead:               409,
	ErrMachineInvalidFingerprint: 400,
	ErrLeaseSignFailed:           500,

	ErrEventNotFound:            404,
	ErrWebhookEventNotFound:     404,
	ErrDeliveryPredatesEventLog: 422,

	ErrEntitlementNotFound:        404,
	ErrEntitlementInvalidCode:     422,
	ErrEntitlementDuplicateCode:   409,
	ErrEntitlementInUse:           409,
	ErrEntitlementCodeImmutable:   422,
	ErrGrantEntitlementNotAllowed: 403,

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
