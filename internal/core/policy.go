package core

import "github.com/google/uuid"

// PolicyID is a typed UUID v7 for policies.
type PolicyID uuid.UUID

// NewPolicyID generates a new PolicyID using UUID v7.
func NewPolicyID() PolicyID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate PolicyID: " + err.Error())
	}
	return PolicyID(id)
}

// ParsePolicyID parses a UUID string into a PolicyID.
func ParsePolicyID(s string) (PolicyID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return PolicyID{}, err
	}
	return PolicyID(id), nil
}

// String returns the string representation of the PolicyID.
func (id PolicyID) String() string { return uuid.UUID(id).String() }

// MarshalText implements encoding.TextMarshaler (used by JSON).
func (id PolicyID) MarshalText() ([]byte, error) { return uuid.UUID(id).MarshalText() }

// UnmarshalText implements encoding.TextUnmarshaler (used by JSON).
func (id *PolicyID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = PolicyID(u)
	return nil
}

// ExpirationStrategy controls what happens when a license passes its
// expires_at timestamp. See spec §Expiration Strategy Semantics.
type ExpirationStrategy string

const (
	ExpirationStrategyMaintainAccess ExpirationStrategy = "MAINTAIN_ACCESS"
	ExpirationStrategyRestrictAccess ExpirationStrategy = "RESTRICT_ACCESS"
	ExpirationStrategyRevokeAccess   ExpirationStrategy = "REVOKE_ACCESS"
)

// IsValid reports whether s is a known strategy value.
func (s ExpirationStrategy) IsValid() bool {
	switch s {
	case ExpirationStrategyMaintainAccess, ExpirationStrategyRestrictAccess, ExpirationStrategyRevokeAccess:
		return true
	}
	return false
}

// ExpirationBasis selects when the expires_at moment is materialized.
type ExpirationBasis string

const (
	ExpirationBasisFromCreation        ExpirationBasis = "FROM_CREATION"
	ExpirationBasisFromFirstActivation ExpirationBasis = "FROM_FIRST_ACTIVATION"
)

// IsValid reports whether b is a known basis value.
func (b ExpirationBasis) IsValid() bool {
	switch b {
	case ExpirationBasisFromCreation, ExpirationBasisFromFirstActivation:
		return true
	}
	return false
}

// ComponentMatchingStrategy is reserved for L5 (Release 4). Present on
// policies in L1 as a scaffold; ignored by L1 enforcement.
type ComponentMatchingStrategy string

const (
	ComponentMatchingAny ComponentMatchingStrategy = "MATCH_ANY"
	ComponentMatchingTwo ComponentMatchingStrategy = "MATCH_TWO"
	ComponentMatchingAll ComponentMatchingStrategy = "MATCH_ALL"
)

// IsValid reports whether s is a known strategy value.
func (s ComponentMatchingStrategy) IsValid() bool {
	switch s {
	case ComponentMatchingAny, ComponentMatchingTwo, ComponentMatchingAll:
		return true
	}
	return false
}
