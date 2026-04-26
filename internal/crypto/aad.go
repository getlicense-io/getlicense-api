package crypto

import "github.com/getlicense-io/getlicense-api/internal/core"

// AAD format strings used by AES-GCM v2 envelopes (PR-C). Each string
// binds a ciphertext to a (entity, id, purpose) tuple so an attacker
// with DB write access cannot swap encrypted columns between rows or
// purposes — GCM auth fails on a mismatched AAD.
//
// The format MUST stay stable. Changing any AAD breaks decryption of
// every existing v2 row written under the old format.
//
// Conventions:
//   - All ASCII, no escaping needed for the embedded UUID (canonical
//     UUID rendering is hex+hyphens).
//   - "{entity}:{id}:{purpose}" so the entity prefix and the purpose
//     suffix are both human-readable when an operator inspects the
//     ciphertext header in pgcli.
//   - Helpers live in the crypto package (not per-service) so all
//     call sites share one definition; drift between encrypt and
//     decrypt sites is a real source of bugs and centralization
//     prevents it.

// WebhookSigningSecretAAD returns the AAD for a webhook endpoint's
// HMAC signing secret. Format: "webhook_endpoint:{id}:signing_secret".
func WebhookSigningSecretAAD(id core.WebhookEndpointID) []byte {
	return []byte("webhook_endpoint:" + id.String() + ":signing_secret")
}

// TOTPSecretAAD returns the AAD for an identity's TOTP secret.
// Format: "identity:{id}:totp_secret".
func TOTPSecretAAD(id core.IdentityID) []byte {
	return []byte("identity:" + id.String() + ":totp_secret")
}

// ProductPrivateKeyAAD returns the AAD for a product's Ed25519
// private key. Format: "product:{id}:private_key".
func ProductPrivateKeyAAD(id core.ProductID) []byte {
	return []byte("product:" + id.String() + ":private_key")
}
