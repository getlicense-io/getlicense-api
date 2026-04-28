// Package crypto provides the cryptographic primitives used by the
// rest of the codebase: Ed25519 product key signing (gl1 license
// tokens, gl2 lease tokens), AES-GCM with mandatory AAD binding,
// HMAC-SHA256 (license key / API key / refresh token hashing),
// HKDF-SHA256 master key derivation, JWT issuing and key-rotation
// verification, TOTP enrollment/verification, and bcrypt password
// hashing. All keys derive from GETLICENSE_MASTER_KEY.
package crypto
