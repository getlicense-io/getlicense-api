package entitlement_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/entitlement"
)

func TestValidateCode(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		wantErr bool
	}{
		{"single uppercase letter", "A", false},
		{"typical feature code", "OFFLINE_SUPPORT", false},
		{"mixed letters and digits", "A_B_C_1", false},
		{"all uppercase", "ABCDEFGHIJ", false},
		{"max length 64 chars", strings.Repeat("A", 64), false},

		{"empty string", "", true},
		{"lowercase", "offline_support", true},
		{"mixed case", "Offline_Support", true},
		{"leading digit", "1FEATURE", true},
		{"leading underscore", "_FEATURE", true},
		{"too long 65 chars", strings.Repeat("A", 65), true},
		{"contains space", "OFFLINE SUPPORT", true},
		{"contains dash", "OFFLINE-SUPPORT", true},
		{"unicode character", "FEATURE_\u00C9", true},
		{"whitespace only", "   ", true},
		{"contains dot", "FEATURE.V2", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := entitlement.ValidateCode(tt.code)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for code %q", tt.code)
				}
				var appErr *core.AppError
				if !errors.As(err, &appErr) || appErr.Code != core.ErrEntitlementInvalidCode {
					t.Errorf("expected ErrEntitlementInvalidCode, got %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for code %q: %v", tt.code, err)
				}
			}
		})
	}
}
