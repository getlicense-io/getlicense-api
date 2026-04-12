package core

import "fmt"

// API key and token prefix constants.
const (
	APIKeyPrefixLive   = "gl_live_"
	APIKeyPrefixTest   = "gl_test_"
	RefreshTokenPrefix = "rt_"
)

// LicenseType represents the billing/expiry model of a license.
type LicenseType string

const (
	LicenseTypePerpetual    LicenseType = "perpetual"
	LicenseTypeTimed        LicenseType = "timed"
	LicenseTypeSubscription LicenseType = "subscription"
	LicenseTypeTrial        LicenseType = "trial"
)

// ParseLicenseType validates and returns a LicenseType from a string.
func ParseLicenseType(s string) (LicenseType, error) {
	switch LicenseType(s) {
	case LicenseTypePerpetual, LicenseTypeTimed, LicenseTypeSubscription, LicenseTypeTrial:
		return LicenseType(s), nil
	default:
		return "", fmt.Errorf("core: invalid license type %q", s)
	}
}

// LicenseStatus represents the current state of a license.
type LicenseStatus string

const (
	LicenseStatusInactive  LicenseStatus = "inactive"
	LicenseStatusActive    LicenseStatus = "active"
	LicenseStatusSuspended LicenseStatus = "suspended"
	LicenseStatusRevoked   LicenseStatus = "revoked"
	LicenseStatusExpired   LicenseStatus = "expired"
)

// CanSuspend returns true if this status allows a suspend transition.
// Only active licenses may be suspended.
func (s LicenseStatus) CanSuspend() bool {
	return s == LicenseStatusActive
}

// CanRevoke returns true if this status allows a revoke transition.
// Active and suspended licenses may be revoked.
func (s LicenseStatus) CanRevoke() bool {
	return s == LicenseStatusActive || s == LicenseStatusSuspended
}

// CanReinstate returns true if this status allows reinstatement back to active.
// Only suspended licenses may be reinstated.
func (s LicenseStatus) CanReinstate() bool {
	return s == LicenseStatusSuspended
}

// UserRole represents the access level of a user within an account.
type UserRole string

const (
	UserRoleOwner  UserRole = "owner"
	UserRoleAdmin  UserRole = "admin"
	UserRoleMember UserRole = "member"
)

// userRoleLevel maps roles to numeric levels for comparison.
var userRoleLevel = map[UserRole]int{
	UserRoleMember: 1,
	UserRoleAdmin:  2,
	UserRoleOwner:  3,
}

// AtLeast returns true when the role's level is greater than or equal to the required role's level.
func (r UserRole) AtLeast(required UserRole) bool {
	return userRoleLevel[r] >= userRoleLevel[required]
}

// Environment represents the API key environment.
type Environment string

const (
	EnvironmentLive Environment = "live"
	EnvironmentTest Environment = "test"
)

// ParseEnvironment validates and returns an Environment from a string.
func ParseEnvironment(s string) (Environment, error) {
	switch Environment(s) {
	case EnvironmentLive, EnvironmentTest:
		return Environment(s), nil
	default:
		return "", fmt.Errorf("core: invalid environment %q", s)
	}
}

// APIKeyScope defines the scope of an API key.
type APIKeyScope string

const (
	APIKeyScopeAccountWide APIKeyScope = "account_wide"
	APIKeyScopeProduct     APIKeyScope = "product"
)

// DeliveryStatus represents the delivery state of a webhook event.
type DeliveryStatus string

const (
	DeliveryStatusPending   DeliveryStatus = "pending"
	DeliveryStatusDelivered DeliveryStatus = "delivered"
	DeliveryStatusFailed    DeliveryStatus = "failed"
)

// EventType represents the type of a webhook event.
type EventType string

const (
	EventTypeLicenseCreated     EventType = "license.created"
	EventTypeLicenseUpdated     EventType = "license.updated"
	EventTypeLicenseActivated   EventType = "license.activated"
	EventTypeLicenseValidated   EventType = "license.validated"
	EventTypeLicenseSuspended   EventType = "license.suspended"
	EventTypeLicenseRevoked     EventType = "license.revoked"
	EventTypeLicenseExpired     EventType = "license.expired"
	EventTypeMachineActivated   EventType = "machine.activated"
	EventTypeMachineDeactivated EventType = "machine.deactivated"
)
