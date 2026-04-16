package licensing

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/policy"
)

// perpetualLeaseSentinel is the lease_expires_at value used when
// require_checkout=false and the license has no expires_at. 9999-01-01
// is far enough in the future that no real client cares, and stays
// well inside int64-second range.
var perpetualLeaseSentinel = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

// ComputeLeaseExpiresAt is a pure function returning the lease expiry
// timestamp for an activation/checkin given the effective policy
// values and the license's optional expires_at.
//
//	require_checkout=true:
//	  min(now + checkout_interval_sec, now + max_checkout_duration_sec)
//	require_checkout=false:
//	  license.expires_at if set, else perpetualLeaseSentinel
func ComputeLeaseExpiresAt(eff policy.Effective, licenseExpiresAt *time.Time, now time.Time) time.Time {
	if eff.RequireCheckout {
		intervalSec := eff.CheckoutIntervalSec
		if eff.MaxCheckoutDurationSec > 0 && eff.MaxCheckoutDurationSec < intervalSec {
			intervalSec = eff.MaxCheckoutDurationSec
		}
		return now.Add(time.Duration(intervalSec) * time.Second)
	}
	if licenseExpiresAt != nil {
		return *licenseExpiresAt
	}
	return perpetualLeaseSentinel
}

// BuildLeaseClaimsInput is the shape passed into BuildLeaseClaims.
// Keeping it as a struct means the call site is order-independent and
// future fields don't shift the function signature.
type BuildLeaseClaimsInput struct {
	LicenseID        core.LicenseID
	ProductID        core.ProductID
	PolicyID         core.PolicyID
	MachineID        core.MachineID
	Fingerprint      string
	LicenseStatus    core.LicenseStatus
	LicenseExpiresAt *time.Time
	LeaseIssuedAt    time.Time
	LeaseExpiresAt   time.Time
	Effective        policy.Effective
	Entitlements     []string
}

// BuildLeaseClaims assembles a LeaseTokenPayload ready for SignLeaseToken.
// Entitlements are populated from the caller-supplied input; nil is
// coalesced to an empty slice for deterministic JSON serialization.
func BuildLeaseClaims(in BuildLeaseClaimsInput) crypto.LeaseTokenPayload {
	var licExpUnix int64
	if in.LicenseExpiresAt != nil {
		licExpUnix = in.LicenseExpiresAt.Unix()
	}
	ent := in.Entitlements
	if ent == nil {
		ent = []string{}
	}
	return crypto.LeaseTokenPayload{
		Version:         1,
		LicenseID:       in.LicenseID.String(),
		ProductID:       in.ProductID.String(),
		PolicyID:        in.PolicyID.String(),
		LicenseStatus:   string(in.LicenseStatus),
		LicenseExpires:  licExpUnix,
		MachineID:       in.MachineID.String(),
		Fingerprint:     in.Fingerprint,
		LeaseIssuedAt:   in.LeaseIssuedAt.Unix(),
		LeaseExpiresAt:  in.LeaseExpiresAt.Unix(),
		RequiresCheckin: in.Effective.RequireCheckout,
		GraceSec:        in.Effective.CheckoutGraceSec,
		Entitlements:    ent,
		IssuedAt:        in.LeaseIssuedAt.Unix(),
		ExpiresAt:       in.LeaseExpiresAt.Unix(),
		JTI:             newJTI(),
	}
}

// newJTI generates a 16-byte random hex string for the lease's jti claim.
// Server does not track issued jtis; the field is reserved for future
// SDK-side replay detection.
func newJTI() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
