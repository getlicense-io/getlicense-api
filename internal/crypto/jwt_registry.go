package crypto

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ImplicitDefaultKID is the kid label assigned to the single
// HKDF-derived signing key when the registry runs in implicit mode
// (no GETLICENSE_JWT_KEYS / GETLICENSE_JWT_KID_CURRENT env vars).
// The value "v0" is a stable kid label, not legacy semantics — every
// JWT minted under implicit mode embeds this kid in the JOSE header
// and the verifier looks it up by kid like any other key.
const ImplicitDefaultKID = "v0"

// JWTKeyRegistry holds one or more named signing keys plus a
// designation for the "current" kid used for new signatures. Verifiers
// look up the kid from the JOSE header and select the matching key —
// there is NO kid-absent fallback. A token without a kid header, or
// with a kid that the registry does not know, is rejected at verify.
//
// The registry supports two configuration modes:
//
//  1. Explicit (recommended for production): the operator sets
//     GETLICENSE_JWT_KEYS=v1:HEX,v2:HEX and GETLICENSE_JWT_KID_CURRENT=v2.
//     New tokens are minted with kid=v2 in the JOSE header. Old tokens
//     bearing kid=v1 still verify against the v1 key. Rotation is
//     "add v2 with v1 still present, wait for max JWT TTL, drop v1".
//
//  2. Implicit (default — convenient for dev): no env vars set. The
//     registry registers a single HKDF-derived key under
//     ImplicitDefaultKID ("v0") and sets that as the current kid.
//     Tokens minted under implicit mode embed kid=v0; the verifier
//     looks up "v0" exactly the same way it would look up any
//     explicitly-configured kid. There is no special-case path.
type JWTKeyRegistry struct {
	keys      map[string][]byte // kid -> 32-byte key
	currentID string            // kid embedded in newly-signed tokens
}

// NewJWTKeyRegistryFromConfig constructs the registry from raw env
// strings.
//
// keysSpec format: "kid1:hex,kid2:hex,..." with each hex value being
// 64 hex characters (32 bytes). When keysSpec is empty the registry
// runs in implicit mode and registers hkdfKey under ImplicitDefaultKID
// as the current kid; hkdfKey is unused in explicit mode.
//
// Validation:
//   - Implicit mode (keysSpec empty): hkdfKey must be non-empty;
//     currentID must be either empty (defaulted) or ImplicitDefaultKID.
//   - Explicit mode (keysSpec non-empty): each entry parses as kid:hex
//     with hex decoding to exactly 32 bytes; currentID must be
//     non-empty and present in the parsed keys; duplicate kids reject.
func NewJWTKeyRegistryFromConfig(keysSpec, currentID string, hkdfKey []byte) (*JWTKeyRegistry, error) {
	reg := &JWTKeyRegistry{
		keys: make(map[string][]byte),
	}

	if strings.TrimSpace(keysSpec) == "" {
		// Implicit mode: register the HKDF-derived key under
		// ImplicitDefaultKID. currentID is allowed to be either empty
		// (default) or ImplicitDefaultKID (explicit but equivalent).
		// Anything else is a misconfiguration that would produce tokens
		// nobody can verify.
		if len(hkdfKey) == 0 {
			return nil, fmt.Errorf("crypto: implicit mode requires a non-empty HKDF-derived key (NewMasterKey must derive it before constructing the registry)")
		}
		if currentID != "" && currentID != ImplicitDefaultKID {
			return nil, fmt.Errorf("crypto: GETLICENSE_JWT_KID_CURRENT=%q but GETLICENSE_JWT_KEYS is empty (no key registered under that kid)", currentID)
		}
		reg.currentID = ImplicitDefaultKID
		reg.keys[ImplicitDefaultKID] = hkdfKey
		return reg, nil
	}

	for _, pair := range strings.Split(keysSpec, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("crypto: invalid GETLICENSE_JWT_KEYS entry %q (expected kid:hex)", pair)
		}
		kid := strings.TrimSpace(parts[0])
		hexValue := strings.TrimSpace(parts[1])
		if kid == "" || hexValue == "" {
			return nil, fmt.Errorf("crypto: invalid GETLICENSE_JWT_KEYS entry %q (kid and hex must both be non-empty)", pair)
		}
		keyBytes, err := hex.DecodeString(hexValue)
		if err != nil {
			return nil, fmt.Errorf("crypto: invalid hex for kid %q: %w", kid, err)
		}
		if len(keyBytes) != 32 {
			return nil, fmt.Errorf("crypto: kid %q must be 32 bytes (64 hex chars), got %d bytes", kid, len(keyBytes))
		}
		if _, dup := reg.keys[kid]; dup {
			return nil, fmt.Errorf("crypto: duplicate kid %q in GETLICENSE_JWT_KEYS", kid)
		}
		reg.keys[kid] = keyBytes
	}

	if len(reg.keys) == 0 {
		return nil, fmt.Errorf("crypto: GETLICENSE_JWT_KEYS parsed to zero keys")
	}
	if strings.TrimSpace(currentID) == "" {
		return nil, fmt.Errorf("crypto: GETLICENSE_JWT_KEYS set but GETLICENSE_JWT_KID_CURRENT empty")
	}
	if _, ok := reg.keys[currentID]; !ok {
		return nil, fmt.Errorf("crypto: GETLICENSE_JWT_KID_CURRENT=%q not present in GETLICENSE_JWT_KEYS", currentID)
	}
	reg.currentID = currentID
	return reg, nil
}

// Current returns the kid that Sign embeds in the JOSE header of new
// tokens.
func (r *JWTKeyRegistry) Current() string { return r.currentID }

// CurrentKey returns the key bytes for the current kid. Used by Sign.
func (r *JWTKeyRegistry) CurrentKey() []byte { return r.keys[r.currentID] }

// Lookup returns the key for the given kid. Empty kid is a defensive
// pre-condition error — production SignJWT always sets a non-empty
// kid, and VerifyJWT rejects tokens without a kid header before
// reaching this function. Unknown kids are rejected.
func (r *JWTKeyRegistry) Lookup(kid string) ([]byte, error) {
	if kid == "" {
		return nil, fmt.Errorf("crypto: kid lookup with empty string")
	}
	key, ok := r.keys[kid]
	if !ok {
		return nil, fmt.Errorf("crypto: unknown JWT kid %q", kid)
	}
	return key, nil
}
