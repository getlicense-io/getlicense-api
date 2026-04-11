package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// HMACSHA256 computes an HMAC-SHA256 hex digest of data using key.
func HMACSHA256(key []byte, data string) string {
	return HMACSHA256Sign(key, []byte(data))
}

// HMACSHA256Sign computes an HMAC-SHA256 hex digest of payload using key.
func HMACSHA256Sign(key, payload []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
