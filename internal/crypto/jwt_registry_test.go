package crypto

import (
	"strings"
	"testing"
)

// hkdfKeyForTest is a fixed 32-byte buffer used as the HKDF-derived
// key in implicit-mode tests. The exact bytes don't matter; what
// matters is length (32) and stability across calls.
func hkdfKeyForTest() []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = 0x42
	}
	return out
}

func TestNewJWTKeyRegistryFromConfig_ImplicitMode(t *testing.T) {
	reg, err := NewJWTKeyRegistryFromConfig("", "", hkdfKeyForTest())
	if err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if reg.Current() != ImplicitDefaultKID {
		t.Errorf("Current(): got %q, want %q", reg.Current(), ImplicitDefaultKID)
	}
	got, err := reg.Lookup(ImplicitDefaultKID)
	if err != nil {
		t.Fatalf("Lookup(v0): %v", err)
	}
	if len(got) != 32 {
		t.Errorf("Lookup(v0) length: got %d, want 32", len(got))
	}
}

func TestNewJWTKeyRegistryFromConfig_ImplicitMode_AcceptsExplicitV0CurrentID(t *testing.T) {
	reg, err := NewJWTKeyRegistryFromConfig("", ImplicitDefaultKID, hkdfKeyForTest())
	if err != nil {
		t.Fatalf("expected ok with current=v0 in implicit mode, got %v", err)
	}
	if reg.Current() != ImplicitDefaultKID {
		t.Errorf("Current(): got %q, want %q", reg.Current(), ImplicitDefaultKID)
	}
}

func TestNewJWTKeyRegistryFromConfig_ImplicitMode_RejectsNonV0CurrentID(t *testing.T) {
	_, err := NewJWTKeyRegistryFromConfig("", "v2", hkdfKeyForTest())
	if err == nil {
		t.Error("expected error when current_id is set without keys spec, got nil")
	}
}

func TestNewJWTKeyRegistryFromConfig_ExplicitMode_HappyPath(t *testing.T) {
	v1Hex := strings.Repeat("aa", 32)
	v2Hex := strings.Repeat("bb", 32)
	reg, err := NewJWTKeyRegistryFromConfig("v1:"+v1Hex+", v2:"+v2Hex, "v2", hkdfKeyForTest())
	if err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if reg.Current() != "v2" {
		t.Errorf("Current(): got %q, want %q", reg.Current(), "v2")
	}
	for _, kid := range []string{"v1", "v2"} {
		k, err := reg.Lookup(kid)
		if err != nil || len(k) != 32 {
			t.Errorf("Lookup(%q): got %d bytes (err=%v), want 32 bytes", kid, len(k), err)
		}
	}
	// Empty kid is a defensive pre-condition error — there is no
	// fallback path in the strict-kid model.
	if _, err := reg.Lookup(""); err == nil {
		t.Error("Lookup(empty): expected error, got nil")
	}
}

func TestNewJWTKeyRegistryFromConfig_ExplicitMode_RejectsCurrentMissingFromKeys(t *testing.T) {
	v1Hex := strings.Repeat("aa", 32)
	_, err := NewJWTKeyRegistryFromConfig("v1:"+v1Hex, "v2", hkdfKeyForTest())
	if err == nil {
		t.Error("expected error when current_id is not in keys, got nil")
	}
}

func TestNewJWTKeyRegistryFromConfig_ExplicitMode_RejectsEmptyCurrent(t *testing.T) {
	v1Hex := strings.Repeat("aa", 32)
	_, err := NewJWTKeyRegistryFromConfig("v1:"+v1Hex, "", hkdfKeyForTest())
	if err == nil {
		t.Error("expected error when keys is set but current_id is empty, got nil")
	}
}

func TestNewJWTKeyRegistryFromConfig_RejectsMalformedEntry(t *testing.T) {
	cases := []string{
		"badentry",                       // no colon
		":nokid",                         // empty kid
		"nohex:",                         // empty hex
		"v1:nothex",                      // bad hex
		"v1:" + strings.Repeat("a", 5),   // odd-length hex
		"v1:" + strings.Repeat("aa", 16), // 16 bytes — too short
	}
	for _, spec := range cases {
		_, err := NewJWTKeyRegistryFromConfig(spec, "v1", hkdfKeyForTest())
		if err == nil {
			t.Errorf("expected error for spec %q, got nil", spec)
		}
	}
}

func TestNewJWTKeyRegistryFromConfig_RejectsDuplicateKid(t *testing.T) {
	v1Hex := strings.Repeat("aa", 32)
	v1HexAgain := strings.Repeat("bb", 32)
	_, err := NewJWTKeyRegistryFromConfig("v1:"+v1Hex+",v1:"+v1HexAgain, "v1", hkdfKeyForTest())
	if err == nil {
		t.Error("expected error for duplicate kid, got nil")
	}
}

func TestNewJWTKeyRegistryFromConfig_ImplicitMode_RejectsEmptyHKDFKey(t *testing.T) {
	_, err := NewJWTKeyRegistryFromConfig("", "", nil)
	if err == nil {
		t.Error("expected error for nil hkdf key in implicit mode, got nil")
	}
}

func TestJWTKeyRegistry_Lookup_UnknownKid(t *testing.T) {
	v1Hex := strings.Repeat("aa", 32)
	reg, err := NewJWTKeyRegistryFromConfig("v1:"+v1Hex, "v1", hkdfKeyForTest())
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	if _, err := reg.Lookup("v999"); err == nil {
		t.Error("Lookup(unknown): expected error, got nil")
	}
}

func TestJWTKeyRegistry_Lookup_EmptyKid(t *testing.T) {
	reg, err := NewJWTKeyRegistryFromConfig("", "", hkdfKeyForTest())
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	if _, err := reg.Lookup(""); err == nil {
		t.Error("Lookup(empty): expected defensive error, got nil")
	}
}
