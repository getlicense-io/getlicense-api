package licensing_test

import (
	"testing"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/licensing"
	"github.com/getlicense-io/getlicense-api/internal/policy"
)

func TestComputeLeaseExpiresAt_RequireCheckout(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	eff := policy.Effective{
		RequireCheckout:        true,
		CheckoutIntervalSec:    3600,
		MaxCheckoutDurationSec: 7200,
	}
	got := licensing.ComputeLeaseExpiresAt(eff, nil, now)
	want := now.Add(time.Hour)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestComputeLeaseExpiresAt_CappedByMaxDuration(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	eff := policy.Effective{
		RequireCheckout:        true,
		CheckoutIntervalSec:    7200,
		MaxCheckoutDurationSec: 3600,
	}
	got := licensing.ComputeLeaseExpiresAt(eff, nil, now)
	want := now.Add(time.Hour)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v (capped by max_checkout_duration)", got, want)
	}
}

func TestComputeLeaseExpiresAt_RequireCheckoutFalse_BoundedByLicense(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expires := now.Add(365 * 24 * time.Hour)
	eff := policy.Effective{
		RequireCheckout:     false,
		CheckoutIntervalSec: 3600,
	}
	got := licensing.ComputeLeaseExpiresAt(eff, &expires, now)
	if !got.Equal(expires) {
		t.Errorf("got %v, want license expiry %v", got, expires)
	}
}

func TestComputeLeaseExpiresAt_RequireCheckoutFalse_PerpetualLicense(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	eff := policy.Effective{RequireCheckout: false}
	got := licensing.ComputeLeaseExpiresAt(eff, nil, now)
	want := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestBuildLeaseClaims_PopulatesEverything(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	licExpires := now.Add(365 * 24 * time.Hour)
	leaseExp := now.Add(time.Hour)
	in := licensing.BuildLeaseClaimsInput{
		LicenseID:        core.NewLicenseID(),
		ProductID:        core.NewProductID(),
		PolicyID:         core.NewPolicyID(),
		MachineID:        core.NewMachineID(),
		Fingerprint:      "fp-1",
		LicenseStatus:    core.LicenseStatusActive,
		LicenseExpiresAt: &licExpires,
		LeaseIssuedAt:    now,
		LeaseExpiresAt:   leaseExp,
		Effective: policy.Effective{
			RequireCheckout:  true,
			CheckoutGraceSec: 3600,
		},
	}
	claims := licensing.BuildLeaseClaims(in)
	if claims.LicenseID == "" || claims.ProductID == "" {
		t.Error("ids not populated")
	}
	if claims.LicenseExpires != licExpires.Unix() {
		t.Errorf("LicenseExpires = %d", claims.LicenseExpires)
	}
	if claims.GraceSec != 3600 {
		t.Errorf("GraceSec = %d", claims.GraceSec)
	}
	if !claims.RequiresCheckin {
		t.Error("RequiresCheckin should be true")
	}
	if claims.Entitlements == nil {
		t.Error("Entitlements should be non-nil empty array (L3 placeholder)")
	}
}
