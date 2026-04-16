package entitlement

import (
	"regexp"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

// codeRegex validates entitlement codes: uppercase letter start, then
// uppercase letters, digits, or underscores, 1–64 chars total.
var codeRegex = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// ValidateCode checks that code conforms to the entitlement code format.
// Returns ErrEntitlementInvalidCode on mismatch.
func ValidateCode(code string) error {
	if !codeRegex.MatchString(code) {
		return core.NewAppError(core.ErrEntitlementInvalidCode, "entitlement code must match ^[A-Z][A-Z0-9_]{0,63}$")
	}
	return nil
}
