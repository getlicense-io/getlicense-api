package core

import (
	"fmt"
	"regexp"
	"time"
)

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

// Environment is a per-account data partition slug. Live/Test are
// auto-seeded; additional slugs may be user-defined.
type Environment string

const (
	EnvironmentLive Environment = "live"
	EnvironmentTest Environment = "test"
)

// Matches the CHECK constraint on environments.slug in migration 014.
var environmentSlugRegex = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// ParseEnvironment validates slug FORMAT only; existence is enforced
// by RLS on downstream queries.
func ParseEnvironment(s string) (Environment, error) {
	if !environmentSlugRegex.MatchString(s) {
		return "", fmt.Errorf("core: invalid environment %q", s)
	}
	return Environment(s), nil
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
	EventTypeLicenseReinstated  EventType = "license.reinstated"
	EventTypeLicenseExpired     EventType = "license.expired"
	EventTypeMachineActivated   EventType = "machine.activated"
	EventTypeMachineDeactivated EventType = "machine.deactivated"
)

// ValidateLicenseStatus checks that the license status allows normal operation.
// It returns a typed AppError for revoked, suspended, inactive, and expired
// licenses. An active license with a past expiry is also treated as expired.
func ValidateLicenseStatus(status LicenseStatus, expiresAt *time.Time) error {
	switch status {
	case LicenseStatusRevoked:
		return NewAppError(ErrLicenseRevoked, "License has been revoked")
	case LicenseStatusSuspended:
		return NewAppError(ErrLicenseSuspended, "License is suspended")
	case LicenseStatusInactive:
		return NewAppError(ErrLicenseInactive, "License is inactive")
	case LicenseStatusExpired:
		return NewAppError(ErrLicenseExpired, "License has expired")
	case LicenseStatusActive:
		if expiresAt != nil && expiresAt.Before(time.Now()) {
			return NewAppError(ErrLicenseExpired, "License has expired")
		}
		return nil
	default:
		return nil
	}
}
