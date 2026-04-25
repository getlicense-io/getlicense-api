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

// TestRetrySchedule_Count guards the worker-pool retry budget. Six
// entries = six retries after the initial attempt = seven total
// attempts before MarkFailedFinal. Changing the schedule length
// changes durable production behavior — bump the count here only
// after deciding the new shape on purpose.
func TestRetrySchedule_Count(t *testing.T) {
	if len(retrySchedule) != 6 {
		t.Errorf("expected 6 retry schedule entries, got %d", len(retrySchedule))
	}
}
