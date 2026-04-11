package crypto

import (
	"testing"
)

var testHMACKey = []byte("test-hmac-key-32-bytes-long!!!!!")

func TestHMACSHA256_Deterministic(t *testing.T) {
	h1 := HMACSHA256(testHMACKey, "hello world")
	h2 := HMACSHA256(testHMACKey, "hello world")
	if h1 != h2 {
		t.Errorf("HMACSHA256 not deterministic: %q != %q", h1, h2)
	}
}

func TestHMACSHA256_DifferentInputs(t *testing.T) {
	h1 := HMACSHA256(testHMACKey, "hello world")
	h2 := HMACSHA256(testHMACKey, "hello world!")
	if h1 == h2 {
		t.Error("HMACSHA256: different inputs produced same output")
	}
}

func TestHMACSHA256_DifferentKeys(t *testing.T) {
	key1 := []byte("key-one-32-bytes-long!!!!!!!!!!!")
	key2 := []byte("key-two-32-bytes-long!!!!!!!!!!!")
	h1 := HMACSHA256(key1, "hello world")
	h2 := HMACSHA256(key2, "hello world")
	if h1 == h2 {
		t.Error("HMACSHA256: different keys produced same output")
	}
}

func TestHMACSHA256_OutputLength(t *testing.T) {
	h := HMACSHA256(testHMACKey, "hello world")
	if len(h) != 64 {
		t.Errorf("HMACSHA256: expected 64-char hex output, got %d", len(h))
	}
}

func TestHMACSHA256Sign_Deterministic(t *testing.T) {
	payload := []byte("test payload bytes")
	h1 := HMACSHA256Sign(testHMACKey, payload)
	h2 := HMACSHA256Sign(testHMACKey, payload)
	if h1 != h2 {
		t.Errorf("HMACSHA256Sign not deterministic: %q != %q", h1, h2)
	}
}

func TestHMACSHA256Sign_OutputLength(t *testing.T) {
	h := HMACSHA256Sign(testHMACKey, []byte("test"))
	if len(h) != 64 {
		t.Errorf("HMACSHA256Sign: expected 64-char hex output, got %d", len(h))
	}
}

func TestHMACSHA256_ConsistencyBetweenFunctions(t *testing.T) {
	data := "consistent data"
	h1 := HMACSHA256(testHMACKey, data)
	h2 := HMACSHA256Sign(testHMACKey, []byte(data))
	if h1 != h2 {
		t.Errorf("HMACSHA256 and HMACSHA256Sign produced different results: %q vs %q", h1, h2)
	}
}
