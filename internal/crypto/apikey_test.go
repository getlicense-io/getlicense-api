package crypto

import (
	"strings"
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

func TestGenerateAPIKey_Live(t *testing.T) {
	raw, prefix, err := GenerateAPIKey("live")
	if err != nil {
		t.Fatalf("GenerateAPIKey(live) error: %v", err)
	}

	if !strings.HasPrefix(raw, core.APIKeyPrefixLive) {
		t.Errorf("live key missing prefix %q: %q", core.APIKeyPrefixLive, raw)
	}

	// gl_live_ (8) + 64 hex = 72 total
	expectedLen := len(core.APIKeyPrefixLive) + 64
	if len(raw) != expectedLen {
		t.Errorf("live key length: got %d, want %d", len(raw), expectedLen)
	}

	if len(prefix) != 20 {
		t.Errorf("live prefix length: got %d, want 20", len(prefix))
	}

	if prefix != raw[:20] {
		t.Errorf("prefix is not first 20 chars of raw key")
	}
}

func TestGenerateAPIKey_Test(t *testing.T) {
	raw, prefix, err := GenerateAPIKey("test")
	if err != nil {
		t.Fatalf("GenerateAPIKey(test) error: %v", err)
	}

	if !strings.HasPrefix(raw, core.APIKeyPrefixTest) {
		t.Errorf("test key missing prefix %q: %q", core.APIKeyPrefixTest, raw)
	}

	// gl_test_ (8) + 64 hex = 72 total
	expectedLen := len(core.APIKeyPrefixTest) + 64
	if len(raw) != expectedLen {
		t.Errorf("test key length: got %d, want %d", len(raw), expectedLen)
	}

	if len(prefix) != 20 {
		t.Errorf("test prefix length: got %d, want 20", len(prefix))
	}
}

func TestGenerateAPIKey_InvalidEnvironment(t *testing.T) {
	_, _, err := GenerateAPIKey("staging")
	if err == nil {
		t.Error("GenerateAPIKey: expected error for invalid environment, got nil")
	}
}

func TestGenerateAPIKey_Uniqueness(t *testing.T) {
	raw1, _, err := GenerateAPIKey("live")
	if err != nil {
		t.Fatal(err)
	}
	raw2, _, err := GenerateAPIKey("live")
	if err != nil {
		t.Fatal(err)
	}
	if raw1 == raw2 {
		t.Error("GenerateAPIKey: consecutive calls returned identical keys")
	}
}

func TestGenerateRefreshToken_Format(t *testing.T) {
	token, err := GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken error: %v", err)
	}

	if !strings.HasPrefix(token, core.RefreshTokenPrefix) {
		t.Errorf("refresh token missing %q prefix: %q", core.RefreshTokenPrefix, token)
	}

	// rt_ (3) + 64 hex = 67 total
	expectedLen := len(core.RefreshTokenPrefix) + 64
	if len(token) != expectedLen {
		t.Errorf("refresh token length: got %d, want %d", len(token), expectedLen)
	}
}

func TestGenerateRefreshToken_Uniqueness(t *testing.T) {
	t1, err := GenerateRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	t2, err := GenerateRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	if t1 == t2 {
		t.Error("GenerateRefreshToken: consecutive calls returned identical tokens")
	}
}
