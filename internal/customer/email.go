package customer

import (
	"regexp"
	"strings"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

// Conservative RFC-ish email regex used across the codebase. Matches
// the existing Release 1 pattern in auth/signup validation. It does NOT
// validate full RFC 5321 — it catches common format errors.
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// NormalizeEmail returns the trimmed, lowercased form of email. Returns
// ErrCustomerInvalidEmail if the input does not match the email regex.
// Callers must use the returned value for any DB comparison — the unique
// index on customers(account_id, lower(email)) expects lowercased input.
func NormalizeEmail(email string) (string, error) {
	trimmed := strings.TrimSpace(email)
	lowered := strings.ToLower(trimmed)
	if lowered == "" || !emailRegex.MatchString(lowered) {
		return "", core.NewAppError(core.ErrCustomerInvalidEmail, "invalid email format")
	}
	return lowered, nil
}
