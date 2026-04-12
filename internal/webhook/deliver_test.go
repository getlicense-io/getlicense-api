package webhook

import (
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/crypto"
)

func TestHMACSigning_HexLength(t *testing.T) {
	sig := crypto.HMACSHA256Sign([]byte("test-secret"), []byte(`{"event":"test"}`))
	if len(sig) != 64 {
		t.Errorf("expected 64-char hex signature, got %d chars: %s", len(sig), sig)
	}
}

func TestRetryDelays_Count(t *testing.T) {
	if len(retryDelays) != 5 {
		t.Errorf("expected 5 retry delays, got %d", len(retryDelays))
	}
}
