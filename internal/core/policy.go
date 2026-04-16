package core

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
