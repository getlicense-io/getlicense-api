package policy_test

import (
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/policy"
)

func intPtr(v int) *int { return &v }

func TestResolve_NoOverrides(t *testing.T) {
	p := &domain.Policy{
		MaxMachines:            intPtr(3),
		MaxSeats:               intPtr(10),
		Floating:               true,
		Strict:                 false,
		DurationSeconds:        intPtr(86400),
		ExpirationStrategy:     core.ExpirationStrategyRevokeAccess,
		ExpirationBasis:        core.ExpirationBasisFromCreation,
		RequireCheckout:        true,
		CheckoutIntervalSec:    3600,
		MaxCheckoutDurationSec: 7200,
	}
	eff := policy.Resolve(p, domain.LicenseOverrides{})
	if got := *eff.MaxMachines; got != 3 {
		t.Errorf("MaxMachines = %d, want 3", got)
	}
	if eff.CheckoutIntervalSec != 3600 {
		t.Errorf("CheckoutIntervalSec = %d, want 3600", eff.CheckoutIntervalSec)
	}
	if !eff.Floating {
		t.Error("Floating = false, want true")
	}
}

func TestResolve_OverrideMaxMachines(t *testing.T) {
	p := &domain.Policy{MaxMachines: intPtr(3), CheckoutIntervalSec: 3600, MaxCheckoutDurationSec: 7200}
	o := domain.LicenseOverrides{MaxMachines: intPtr(10)}
	eff := policy.Resolve(p, o)
	if got := *eff.MaxMachines; got != 10 {
		t.Errorf("MaxMachines = %d, want 10 (override)", got)
	}
}

func TestResolve_OverrideMaxMachinesToNil(t *testing.T) {
	// Note: nil override means "inherit from policy". Clearing an
	// existing override is done by writing nil back at the API layer.
	p := &domain.Policy{MaxMachines: intPtr(3), CheckoutIntervalSec: 3600, MaxCheckoutDurationSec: 7200}
	o := domain.LicenseOverrides{MaxMachines: nil}
	eff := policy.Resolve(p, o)
	if got := *eff.MaxMachines; got != 3 {
		t.Errorf("MaxMachines = %d, want 3 (inherit)", got)
	}
}

func TestResolve_BehavioralFlagsNotOverridable(t *testing.T) {
	// Floating/Strict/ExpirationStrategy have no override fields.
	// This test locks in that they always come from the policy.
	p := &domain.Policy{
		Floating:           true,
		Strict:             true,
		ExpirationStrategy: core.ExpirationStrategyMaintainAccess,
	}
	eff := policy.Resolve(p, domain.LicenseOverrides{})
	if !eff.Floating || !eff.Strict {
		t.Error("behavioral flags should cascade from policy")
	}
	if eff.ExpirationStrategy != core.ExpirationStrategyMaintainAccess {
		t.Errorf("strategy = %v, want MAINTAIN_ACCESS", eff.ExpirationStrategy)
	}
}

func TestResolve_CheckoutGraceSecCascadesFromPolicy(t *testing.T) {
	p := &domain.Policy{
		CheckoutIntervalSec:    3600,
		MaxCheckoutDurationSec: 7200,
		CheckoutGraceSec:       1800,
	}
	eff := policy.Resolve(p, domain.LicenseOverrides{})
	if eff.CheckoutGraceSec != 1800 {
		t.Errorf("CheckoutGraceSec = %d, want 1800", eff.CheckoutGraceSec)
	}
}

func TestResolve_OverrideCheckoutFields(t *testing.T) {
	p := &domain.Policy{CheckoutIntervalSec: 3600, MaxCheckoutDurationSec: 7200}
	o := domain.LicenseOverrides{
		CheckoutIntervalSec:    intPtr(1800),
		MaxCheckoutDurationSec: intPtr(3600),
	}
	eff := policy.Resolve(p, o)
	if eff.CheckoutIntervalSec != 1800 {
		t.Errorf("CheckoutIntervalSec = %d, want 1800", eff.CheckoutIntervalSec)
	}
	if eff.MaxCheckoutDurationSec != 3600 {
		t.Errorf("MaxCheckoutDurationSec = %d, want 3600", eff.MaxCheckoutDurationSec)
	}
}
