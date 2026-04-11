package webhook

import (
	"testing"
)

func TestSignPayload_HexLength(t *testing.T) {
	sig := SignPayload("test-secret", []byte(`{"event":"test"}`))
	if len(sig) != 64 {
		t.Errorf("expected 64-char hex signature, got %d chars: %s", len(sig), sig)
	}
}

func TestRetryDelays_Count(t *testing.T) {
	if len(RetryDelays) != 5 {
		t.Errorf("expected 5 retry delays, got %d", len(RetryDelays))
	}
}
