package policy

import (
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

// Decision is the output of EvaluateExpiration: whether a license
// should be treated as valid given its policy's expiration strategy
// and its expires_at value. Shared between Validate, Activate, and Checkin.
type Decision struct {
	Valid bool
	Code  core.ErrorCode // populated only when Valid is false
}

// EvaluateExpiration applies the policy's expiration strategy to a
// nullable expires_at timestamp and returns the validation decision.
// Pure function; does not touch the DB.
func EvaluateExpiration(eff Effective, expiresAt *time.Time) Decision {
	if expiresAt == nil {
		return Decision{Valid: true}
	}
	if time.Now().Before(*expiresAt) {
		return Decision{Valid: true}
	}
	// Past expires_at
	switch eff.ExpirationStrategy {
	case core.ExpirationStrategyMaintainAccess:
		return Decision{Valid: true}
	case core.ExpirationStrategyRestrictAccess, core.ExpirationStrategyRevokeAccess:
		return Decision{Valid: false, Code: core.ErrLicenseExpired}
	}
	// Unknown strategy: fail closed.
	return Decision{Valid: false, Code: core.ErrLicenseExpired}
}
