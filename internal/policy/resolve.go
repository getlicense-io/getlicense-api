// Package policy owns policy CRUD and pure effective-value resolution.
// No code outside this package should read Policy raw fields for
// enforcement decisions — always go through Resolve.
package policy

import (
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Effective is the resolved view of a (Policy, LicenseOverrides) pair.
// Only quantitative fields are overridable; behavioral flags come from
// the policy unchanged.
type Effective struct {
	MaxMachines            *int
	MaxSeats               *int
	Floating               bool
	Strict                 bool
	DurationSeconds        *int
	ExpirationStrategy     core.ExpirationStrategy
	ExpirationBasis        core.ExpirationBasis
	RequireCheckout        bool
	CheckoutIntervalSec    int
	MaxCheckoutDurationSec int
	CheckoutGraceSec       int
	// Nil when neither policy nor override set it; the licensing layer
	// applies the server default (GETLICENSE_DEFAULT_VALIDATION_TTL_SEC)
	// before signing tokens. Keeping it *int here lets callers that don't
	// sign tokens (e.g. freeze snapshots) observe the "unset" state.
	ValidationTTLSec *int
}

// Resolve computes the Effective view for a policy + overrides pair.
// Pure function; safe to call concurrently.
func Resolve(p *domain.Policy, o domain.LicenseOverrides) Effective {
	eff := Effective{
		MaxMachines:            p.MaxMachines,
		MaxSeats:               p.MaxSeats,
		Floating:               p.Floating,
		Strict:                 p.Strict,
		DurationSeconds:        p.DurationSeconds,
		ExpirationStrategy:     p.ExpirationStrategy,
		ExpirationBasis:        p.ExpirationBasis,
		RequireCheckout:        p.RequireCheckout,
		CheckoutIntervalSec:    p.CheckoutIntervalSec,
		MaxCheckoutDurationSec: p.MaxCheckoutDurationSec,
		CheckoutGraceSec:       p.CheckoutGraceSec,
		ValidationTTLSec:       p.ValidationTTLSec,
	}
	if o.MaxMachines != nil {
		eff.MaxMachines = o.MaxMachines
	}
	if o.MaxSeats != nil {
		eff.MaxSeats = o.MaxSeats
	}
	if o.CheckoutIntervalSec != nil {
		eff.CheckoutIntervalSec = *o.CheckoutIntervalSec
	}
	if o.MaxCheckoutDurationSec != nil {
		eff.MaxCheckoutDurationSec = *o.MaxCheckoutDurationSec
	}
	if o.ValidationTTLSec != nil {
		eff.ValidationTTLSec = o.ValidationTTLSec
	}
	return eff
}
