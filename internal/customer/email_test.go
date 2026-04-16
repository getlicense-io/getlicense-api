package customer_test

import (
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/customer"
)

func TestNormalizeEmail(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Alice@Example.COM", "alice@example.com"},
		{"  bob@example.org  ", "bob@example.org"},
		{"carol@example.com", "carol@example.com"},
	}
	for _, c := range cases {
		got, err := customer.NormalizeEmail(c.in)
		if err != nil {
			t.Errorf("NormalizeEmail(%q) error = %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeEmail_Invalid(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"not-an-email",
		"@example.com",
		"foo@",
		"foo bar@example.com",
	}
	for _, in := range cases {
		if _, err := customer.NormalizeEmail(in); err == nil {
			t.Errorf("NormalizeEmail(%q) unexpectedly succeeded", in)
		}
	}
}
