package search

import (
	"errors"
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *ParsedQuery
		wantErr string
	}{
		{
			name:  "bare word",
			input: "john@",
			want: &ParsedQuery{
				Bare:    "john@",
				Filters: map[string]string{},
			},
		},
		{
			name:  "type and field filter",
			input: "type:license key:GETL",
			want: &ParsedQuery{
				Types:   []string{"license"},
				Filters: map[string]string{"key": "GETL"},
			},
		},
		{
			name:  "multiple filters same type",
			input: "type:customer email:john name:doe",
			want: &ParsedQuery{
				Types:   []string{"customer"},
				Filters: map[string]string{"email": "john", "name": "doe"},
			},
		},
		{
			name:  "multiple types",
			input: "type:license type:customer email:john@",
			want: &ParsedQuery{
				Types:   []string{"license", "customer"},
				Filters: map[string]string{"email": "john@"},
			},
		},
		{
			name:  "bare word with no type restriction",
			input: "john@example.com",
			want: &ParsedQuery{
				Bare:    "john@example.com",
				Filters: map[string]string{},
			},
		},
		{
			name:  "machine fingerprint",
			input: "type:machine fingerprint:abc123",
			want: &ParsedQuery{
				Types:   []string{"machine"},
				Filters: map[string]string{"fingerprint": "abc123"},
			},
		},
		{
			name:  "product slug",
			input: "type:product slug:my-prod",
			want: &ParsedQuery{
				Types:   []string{"product"},
				Filters: map[string]string{"slug": "my-prod"},
			},
		},
		{
			name:  "license status filter",
			input: "type:license status:active",
			want: &ParsedQuery{
				Types:   []string{"license"},
				Filters: map[string]string{"status": "active"},
			},
		},
		{
			name:  "bare word and filter combined",
			input: "john type:license",
			want: &ParsedQuery{
				Types:   []string{"license"},
				Bare:    "john",
				Filters: map[string]string{},
			},
		},
		{
			name:  "no type with valid cross-type field",
			input: "email:test@",
			want: &ParsedQuery{
				Filters: map[string]string{"email": "test@"},
			},
		},

		// Error cases
		{
			name:    "empty input",
			input:   "",
			wantErr: "search query must not be empty",
		},
		{
			name:    "whitespace only",
			input:   "   ",
			wantErr: "search query must not be empty",
		},
		{
			name:    "unknown type",
			input:   "type:foobar key:x",
			wantErr: "unknown search type",
		},
		{
			name:    "unknown field for type",
			input:   "type:license slug:my-prod",
			wantErr: "unknown filter",
		},
		{
			name:    "unknown field globally",
			input:   "foobar:value",
			wantErr: "unknown filter",
		},
		{
			name:    "field valid for different type",
			input:   "type:product key:GETL",
			wantErr: "unknown filter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.input)
			if tt.wantErr != "" {
				require.Error(t, err)
				var appErr *core.AppError
				require.True(t, errors.As(err, &appErr))
				assert.Contains(t, appErr.Message, tt.wantErr)
				assert.Equal(t, core.ErrValidationError, appErr.Code)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want.Bare, got.Bare)
			assert.Equal(t, tt.want.Types, got.Types)
			assert.Equal(t, tt.want.Filters, got.Filters)
		})
	}
}
