package licensing

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/audit"
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// --- Activate tests ---

func TestActivate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	maxM := 3
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &maxM
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	result, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-abc-123",
	}, audit.Attribution{})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "fp-abc-123", result.Machine.Fingerprint)
	assert.Equal(t, created.License.ID, result.Machine.LicenseID)
	assert.Equal(t, testAccountID, result.Machine.AccountID)
	assert.NotEmpty(t, result.LeaseToken)
	assert.True(t, strings.HasPrefix(result.LeaseToken, "gl2."))
}

func TestActivate_DuplicateFingerprint_Idempotent(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	maxM := 3
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &maxM
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	first, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-dup",
	}, audit.Attribution{})
	require.NoError(t, err)

	// Re-activate same fingerprint is idempotent — reuses the machine ID.
	second, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-dup",
	}, audit.Attribution{})
	require.NoError(t, err)
	assert.Equal(t, first.Machine.ID, second.Machine.ID)
}

func TestActivate_MachineLimitExceeded_FromPolicy(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	maxM := 2
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &maxM
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	for _, fp := range []string{"fp-1", "fp-2"} {
		_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
			Fingerprint: fp,
		}, audit.Attribution{})
		require.NoError(t, err)
	}

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-3",
	}, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrMachineLimitExceeded, appErr.Code)
}

func TestActivate_MachineLimitFromOverrideBeatsPolicy(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	// Policy caps at 1 but the per-license override raises it to 3.
	policyCap := 1
	overrideCap := 3
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &policyCap
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Overrides: domain.LicenseOverrides{MaxMachines: &overrideCap},
		Customer:  inlineCustomer("user@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	for _, fp := range []string{"fp-a", "fp-b", "fp-c"} {
		_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
			Fingerprint: fp,
		}, audit.Attribution{})
		require.NoError(t, err)
	}
}

func TestActivate_LicenseNotFound(t *testing.T) {
	env := newTestEnv(t)

	_, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, core.NewLicenseID(), ActivateRequest{
		Fingerprint: "fp-orphan",
	}, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseNotFound, appErr.Code)
}

func TestActivate_RevokedLicense_ReturnsError(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	// Force the license into a revoked state directly in the mock so
	// Activate hits the terminal-status guard before any policy lookup.
	env.licenses.byID[created.License.ID].Status = core.LicenseStatusRevoked

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-revoked",
	}, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseRevoked, appErr.Code)
}

func TestActivate_SuspendedLicense_ReturnsError(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	env.licenses.byID[created.License.ID].Status = core.LicenseStatusSuspended

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-suspended",
	}, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseSuspended, appErr.Code)
}

func TestActivate_ExpiredLicense_ReturnsError(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	env.licenses.byID[created.License.ID].Status = core.LicenseStatusExpired

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-expired",
	}, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseExpired, appErr.Code)
}

func TestActivate_NoMachineLimit(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	for i := range 5 {
		fp := "fp-" + string(rune('a'+i))
		_, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
			Fingerprint: fp,
		}, audit.Attribution{})
		require.NoError(t, err)
	}
}

func TestActivate_FromFirstActivation_StampsFirstActivatedAtAndExpiresAt(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	dur := 7 * 24 * 60 * 60
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.DurationSeconds = &dur
		p.ExpirationBasis = core.ExpirationBasisFromFirstActivation
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	assert.Nil(t, created.License.ExpiresAt)

	before := time.Now().UTC()
	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-first",
	}, audit.Attribution{})
	require.NoError(t, err)
	after := time.Now().UTC()

	stored := env.licenses.byID[created.License.ID]
	require.NotNil(t, stored.FirstActivatedAt)
	assert.True(t, !stored.FirstActivatedAt.Before(before) && !stored.FirstActivatedAt.After(after))
	require.NotNil(t, stored.ExpiresAt)
	assert.True(t, stored.ExpiresAt.After(before.Add(time.Duration(dur)*time.Second-time.Second)))

	// A second activation must not re-stamp first_activated_at.
	origStamp := *stored.FirstActivatedAt
	time.Sleep(2 * time.Millisecond)
	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-second",
	}, audit.Attribution{})
	require.NoError(t, err)
	assert.Equal(t, origStamp, *stored.FirstActivatedAt)
}

// --- Deactivate tests ---

func TestDeactivate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-remove",
	}, audit.Attribution{})
	require.NoError(t, err)

	err = env.svc.Deactivate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, DeactivateRequest{
		Fingerprint: "fp-remove",
	}, audit.Attribution{})
	require.NoError(t, err)

	key := machineKey(created.License.ID, "fp-remove")
	_, ok := env.machines.byFingerprint[key]
	assert.False(t, ok)
}

func TestDeactivate_EmptyFingerprint(t *testing.T) {
	env := newTestEnv(t)

	err := env.svc.Deactivate(context.Background(), testAccountID, core.EnvironmentLive, core.NewLicenseID(), DeactivateRequest{
		Fingerprint: "",
	}, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

// --- Checkin tests ---

func TestCheckin_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.RequireCheckout = true
		p.CheckoutIntervalSec = 3600
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	activated, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-1",
	}, audit.Attribution{})
	require.NoError(t, err)
	originalLeaseExp := activated.Machine.LeaseExpiresAt

	// Wait one tick to ensure lease times advance.
	time.Sleep(10 * time.Millisecond)

	checkin, err := env.svc.Checkin(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, "fp-1", audit.Attribution{})
	require.NoError(t, err)
	if !checkin.Machine.LeaseExpiresAt.After(originalLeaseExp) {
		t.Errorf("checkin lease should be later than initial activation lease")
	}
	assert.NotEmpty(t, checkin.LeaseToken)
	assert.True(t, strings.HasPrefix(checkin.LeaseToken, "gl2."))
	assert.NotEmpty(t, checkin.LeaseClaims.LicenseID)
}

func TestCheckin_DeadMachineRejected(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	activated, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{Fingerprint: "fp-1"}, audit.Attribution{})
	require.NoError(t, err)

	// Force dead status via the mock.
	env.machines.byID[activated.Machine.ID].Status = core.MachineStatusDead

	_, err = env.svc.Checkin(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, "fp-1", audit.Attribution{})
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrMachineDead {
		t.Errorf("want machine_dead, got %v", err)
	}
}

func TestActivate_ResurrectsDeadMachine(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	first, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{Fingerprint: "fp-1"}, audit.Attribution{})
	require.NoError(t, err)
	originalID := first.Machine.ID

	// Mark dead.
	env.machines.byID[originalID].Status = core.MachineStatusDead

	// Re-activate same fingerprint.
	second, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{Fingerprint: "fp-1"}, audit.Attribution{})
	require.NoError(t, err)
	assert.Equal(t, originalID, second.Machine.ID, "resurrection should reuse machine id")
	assert.Equal(t, core.MachineStatusActive, second.Machine.Status, "resurrected machine should be active")
}

func TestActivate_DeadMachinesDontCountTowardCap(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	one := 1
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &one
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("u@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	// Activate and kill.
	first, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{Fingerprint: "fp-a"}, audit.Attribution{})
	require.NoError(t, err)
	env.machines.byID[first.Machine.ID].Status = core.MachineStatusDead

	// New fingerprint should now be allowed because dead doesn't count.
	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{Fingerprint: "fp-b"}, audit.Attribution{})
	if err != nil {
		t.Errorf("dead machine should not count toward cap; got %v", err)
	}
}

func TestActivate_StaleStillCounts(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	one := 1
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &one
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("u@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	first, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{Fingerprint: "fp-a"}, audit.Attribution{})
	require.NoError(t, err)
	env.machines.byID[first.Machine.ID].Status = core.MachineStatusStale

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{Fingerprint: "fp-b"}, audit.Attribution{})
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrMachineLimitExceeded {
		t.Errorf("stale should still count; want machine_limit_exceeded, got %v", err)
	}
}

// --- Activate + Entitlements ---

func TestActivate_LeaseTokenContainsEntitlements(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	pol := seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	// Create two entitlements and attach one to the policy.
	entA := seedEntitlement(t, env, testAccountID, "FEATURE_A")
	entB := seedEntitlement(t, env, testAccountID, "FEATURE_B")

	err := env.entitlementSvc.AttachToPolicy(context.Background(), pol.ID, []string{entA.Code}, testAccountID)
	require.NoError(t, err)

	// Create a license and attach entB to the license directly.
	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("ent-test@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	err = env.entitlementSvc.AttachToLicense(context.Background(), created.License.ID, []string{entB.Code}, testAccountID)
	require.NoError(t, err)

	// Seed the license → policy mapping in the fake repo so
	// ResolveEffective can compute the union.
	env.entitlements.SetLicensePolicy(created.License.ID, pol.ID)

	result, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-ent-1",
	}, audit.Attribution{})
	require.NoError(t, err)

	// Lease claims should contain both entitlements sorted.
	assert.Equal(t, []string{"FEATURE_A", "FEATURE_B"}, result.LeaseClaims.Entitlements)
}

// --- ListMachines tests (Frontend Unblock Batch - Task 6) ---

func TestListMachines_VendorCallerSeesMachines(t *testing.T) {
	env := newTestEnv(t)
	lic := seedLicenseForListMachines(t, env, nil) // direct (non-grant) license

	machine := domain.Machine{
		ID:          core.NewMachineID(),
		AccountID:   testAccountID,
		LicenseID:   lic.ID,
		Fingerprint: "fp-1",
		Status:      core.MachineStatusActive,
		Environment: core.EnvironmentLive,
	}
	env.machines.listByLicenseRows = []domain.Machine{machine}

	rows, hasMore, err := env.svc.ListMachines(
		context.Background(),
		testAccountID, core.EnvironmentLive,
		lic.ID, "", core.Cursor{}, 50, nil,
	)
	require.NoError(t, err)
	assert.False(t, hasMore)
	require.Len(t, rows, 1)
	assert.Equal(t, machine.ID, rows[0].ID)
}

func TestListMachines_GranteeWithMatchingGrantSeesMachines(t *testing.T) {
	env := newTestEnv(t)
	grantID := core.NewGrantID()
	lic := seedLicenseForListMachines(t, env, &grantID)

	machine := domain.Machine{
		ID:          core.NewMachineID(),
		AccountID:   testAccountID,
		LicenseID:   lic.ID,
		Fingerprint: "fp-grantee",
		Status:      core.MachineStatusActive,
		Environment: core.EnvironmentLive,
	}
	env.machines.listByLicenseRows = []domain.Machine{machine}

	rows, hasMore, err := env.svc.ListMachines(
		context.Background(),
		testAccountID, core.EnvironmentLive,
		lic.ID, "", core.Cursor{}, 50, &grantID,
	)
	require.NoError(t, err)
	assert.False(t, hasMore)
	require.Len(t, rows, 1)
	assert.Equal(t, machine.ID, rows[0].ID)
}

func TestListMachines_GranteeWithMismatchedGrantGets404(t *testing.T) {
	env := newTestEnv(t)
	ownerGrant := core.NewGrantID()
	otherGrant := core.NewGrantID()
	lic := seedLicenseForListMachines(t, env, &ownerGrant)

	_, _, err := env.svc.ListMachines(
		context.Background(),
		testAccountID, core.EnvironmentLive,
		lic.ID, "", core.Cursor{}, 50, &otherGrant,
	)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseNotFound, appErr.Code)

	// Gate must fire BEFORE the repo call — no machine list leaks.
	assert.Empty(t, env.machines.listByLicenseCalls)
}

func TestListMachines_GranteeOnNonGrantLicenseGets404(t *testing.T) {
	env := newTestEnv(t)
	callerGrant := core.NewGrantID()
	lic := seedLicenseForListMachines(t, env, nil) // license NOT tied to any grant

	_, _, err := env.svc.ListMachines(
		context.Background(),
		testAccountID, core.EnvironmentLive,
		lic.ID, "", core.Cursor{}, 50, &callerGrant,
	)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseNotFound, appErr.Code)
	assert.Empty(t, env.machines.listByLicenseCalls)
}

func TestListMachines_LicenseNotFound(t *testing.T) {
	env := newTestEnv(t)
	unknown := core.NewLicenseID()

	_, _, err := env.svc.ListMachines(
		context.Background(),
		testAccountID, core.EnvironmentLive,
		unknown, "", core.Cursor{}, 50, nil,
	)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseNotFound, appErr.Code)
	assert.Empty(t, env.machines.listByLicenseCalls)
}

func TestListMachines_InvalidStatusFilter(t *testing.T) {
	env := newTestEnv(t)
	lic := seedLicenseForListMachines(t, env, nil)

	_, _, err := env.svc.ListMachines(
		context.Background(),
		testAccountID, core.EnvironmentLive,
		lic.ID, "zombie", core.Cursor{}, 50, nil,
	)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)

	// Validation runs BEFORE opening the tx / hitting the repo.
	assert.Empty(t, env.machines.listByLicenseCalls)
}

func TestListMachines_EmptyStatusFilterPassesThrough(t *testing.T) {
	env := newTestEnv(t)
	lic := seedLicenseForListMachines(t, env, nil)

	_, _, err := env.svc.ListMachines(
		context.Background(),
		testAccountID, core.EnvironmentLive,
		lic.ID, "", core.Cursor{}, 50, nil,
	)
	require.NoError(t, err)

	require.Len(t, env.machines.listByLicenseCalls, 1)
	call := env.machines.listByLicenseCalls[0]
	assert.Equal(t, lic.ID, call.licenseID)
	assert.Equal(t, "", call.statusFilter)
	assert.Equal(t, 50, call.limit)
}

// --- Product-scope gate test for Activate (requireLicenseForUpdate) ---

func TestLicensing_ProductScopedKey_MismatchRejected_OnActivate(t *testing.T) {
	// Exercises requireLicenseForUpdate. Activate is the representative
	// mutation path — the other mutations (Checkin, Update, Freeze,
	// AttachPolicy) share the helper so one test covers the pattern.
	env := newTestEnv(t)
	lic := seedLicenseForListMachines(t, env, nil)
	otherProductID := core.NewProductID()
	ctx := productScopedKeyCtx(otherProductID)

	_, err := env.svc.Activate(ctx, testAccountID, core.EnvironmentLive, lic.ID,
		ActivateRequest{Fingerprint: "fp-test"}, audit.Attribution{})
	require.Error(t, err)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrAPIKeyScopeMismatch, appErr.Code)
}
