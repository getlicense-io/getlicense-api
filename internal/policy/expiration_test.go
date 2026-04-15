package policy_test

import (
	"testing"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/policy"
)

func TestEvaluateExpiration_PastRevoke(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	dec := policy.EvaluateExpiration(policy.Effective{ExpirationStrategy: core.ExpirationStrategyRevokeAccess}, &past)
	if dec.Valid || dec.Code != core.ErrLicenseExpired {
		t.Errorf("revoke past: got %+v, want valid=false code=license_expired", dec)
	}
}

func TestEvaluateExpiration_PastRestrict(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	dec := policy.EvaluateExpiration(policy.Effective{ExpirationStrategy: core.ExpirationStrategyRestrictAccess}, &past)
	if dec.Valid || dec.Code != core.ErrLicenseExpired {
		t.Errorf("restrict past: got %+v, want valid=false code=license_expired", dec)
	}
}

func TestEvaluateExpiration_PastMaintain(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	dec := policy.EvaluateExpiration(policy.Effective{ExpirationStrategy: core.ExpirationStrategyMaintainAccess}, &past)
	if !dec.Valid {
		t.Errorf("maintain past: got %+v, want valid=true", dec)
	}
}

func TestEvaluateExpiration_Future(t *testing.T) {
	future := time.Now().Add(time.Hour)
	for _, s := range []core.ExpirationStrategy{
		core.ExpirationStrategyRevokeAccess,
		core.ExpirationStrategyRestrictAccess,
		core.ExpirationStrategyMaintainAccess,
	} {
		dec := policy.EvaluateExpiration(policy.Effective{ExpirationStrategy: s}, &future)
		if !dec.Valid {
			t.Errorf("strategy=%v future: got invalid, want valid", s)
		}
	}
}

func TestEvaluateExpiration_NilExpiry(t *testing.T) {
	// Perpetual license (expires_at NULL) is always valid regardless of strategy.
	dec := policy.EvaluateExpiration(policy.Effective{ExpirationStrategy: core.ExpirationStrategyRevokeAccess}, nil)
	if !dec.Valid {
		t.Errorf("perpetual: got %+v, want valid", dec)
	}
}
