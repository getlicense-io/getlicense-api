package policy_test

import (
	"context"
	"errors"
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/policy"
)

type fakeRepo struct {
	policies    map[core.PolicyID]*domain.Policy
	refCounts   map[core.PolicyID]int
	defaults    map[core.ProductID]core.PolicyID
	reassignLog []reassignCall
}
type reassignCall struct{ from, to core.PolicyID }

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		policies:  map[core.PolicyID]*domain.Policy{},
		refCounts: map[core.PolicyID]int{},
		defaults:  map[core.ProductID]core.PolicyID{},
	}
}

func (r *fakeRepo) Create(_ context.Context, p *domain.Policy) error {
	r.policies[p.ID] = p
	if p.IsDefault {
		r.defaults[p.ProductID] = p.ID
	}
	return nil
}

// Get returns (nil, nil) on not-found — matches the Release 1 repo contract.
// The service layer is responsible for translating nil into the typed AppError.
func (r *fakeRepo) Get(_ context.Context, id core.PolicyID) (*domain.Policy, error) {
	p, ok := r.policies[id]
	if !ok {
		return nil, nil
	}
	return p, nil
}

func (r *fakeRepo) GetByProduct(context.Context, core.ProductID, core.Cursor, int) ([]domain.Policy, bool, error) {
	return nil, false, nil
}

// GetDefaultForProduct returns (nil, nil) on not-found — Release 1 contract.
func (r *fakeRepo) GetDefaultForProduct(_ context.Context, productID core.ProductID) (*domain.Policy, error) {
	id, ok := r.defaults[productID]
	if !ok {
		return nil, nil
	}
	return r.policies[id], nil
}

func (r *fakeRepo) Update(_ context.Context, p *domain.Policy) error {
	r.policies[p.ID] = p
	return nil
}

func (r *fakeRepo) Delete(_ context.Context, id core.PolicyID) error {
	if _, ok := r.policies[id]; !ok {
		return core.NewAppError(core.ErrPolicyNotFound, "not found")
	}
	delete(r.policies, id)
	return nil
}

func (r *fakeRepo) SetDefault(_ context.Context, productID core.ProductID, id core.PolicyID) error {
	for pid, p := range r.policies {
		if p.ProductID == productID && p.IsDefault {
			p.IsDefault = false
			r.policies[pid] = p
		}
	}
	p, ok := r.policies[id]
	if !ok || p.ProductID != productID {
		return core.NewAppError(core.ErrPolicyProductMismatch, "mismatch")
	}
	p.IsDefault = true
	r.defaults[productID] = id
	return nil
}

func (r *fakeRepo) ReassignLicensesFromPolicy(_ context.Context, from, to core.PolicyID) (int, error) {
	r.reassignLog = append(r.reassignLog, reassignCall{from, to})
	n := r.refCounts[from]
	r.refCounts[from] = 0
	r.refCounts[to] += n
	return n, nil
}

func (r *fakeRepo) CountReferencingLicenses(_ context.Context, id core.PolicyID) (int, error) {
	return r.refCounts[id], nil
}

func TestService_CreateDefault(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	pid := core.NewProductID()
	aid := core.NewAccountID()
	p, err := svc.CreateDefault(context.Background(), aid, pid)
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsDefault {
		t.Error("CreateDefault did not set IsDefault")
	}
	if p.ExpirationStrategy != core.ExpirationStrategyRevokeAccess {
		t.Errorf("default strategy = %v", p.ExpirationStrategy)
	}
	if p.ExpirationBasis != core.ExpirationBasisFromCreation {
		t.Errorf("default basis = %v", p.ExpirationBasis)
	}
	if p.ComponentMatchingStrategy != core.ComponentMatchingAny {
		t.Errorf("default component strategy = %v", p.ComponentMatchingStrategy)
	}
	if p.CheckoutIntervalSec != 86400 {
		t.Errorf("default checkout interval = %d, want 86400", p.CheckoutIntervalSec)
	}
	if p.MaxCheckoutDurationSec != 604800 {
		t.Errorf("default max checkout = %d, want 604800", p.MaxCheckoutDurationSec)
	}
}

func TestService_GetNotFound(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	_, err := svc.Get(context.Background(), core.NewPolicyID())
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrPolicyNotFound {
		t.Errorf("want policy_not_found, got %v", err)
	}
}

func TestService_GetDefaultNotFound(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	_, err := svc.GetDefault(context.Background(), core.NewProductID())
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrPolicyNotFound {
		t.Errorf("want policy_not_found, got %v", err)
	}
}

func TestService_DeleteDefaultBlocked(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	p, _ := svc.CreateDefault(context.Background(), core.NewAccountID(), core.NewProductID())
	err := svc.Delete(context.Background(), p.ID, false)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrPolicyIsDefault {
		t.Errorf("want policy_is_default, got %v", err)
	}
}

func TestService_DeleteInUseWithoutForce(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	aid := core.NewAccountID()
	pid := core.NewProductID()
	_, _ = svc.CreateDefault(context.Background(), aid, pid)
	p, _ := svc.Create(context.Background(), aid, pid, policy.CreateRequest{Name: "extra"}, false)
	repo.refCounts[p.ID] = 3
	err := svc.Delete(context.Background(), p.ID, false)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrPolicyInUse {
		t.Errorf("want policy_in_use, got %v", err)
	}
}

func TestService_DeleteForceReassigns(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	aid := core.NewAccountID()
	pid := core.NewProductID()
	def, _ := svc.CreateDefault(context.Background(), aid, pid)
	p, _ := svc.Create(context.Background(), aid, pid, policy.CreateRequest{Name: "extra"}, false)
	repo.refCounts[p.ID] = 5
	if err := svc.Delete(context.Background(), p.ID, true); err != nil {
		t.Fatal(err)
	}
	if len(repo.reassignLog) != 1 || repo.reassignLog[0].from != p.ID || repo.reassignLog[0].to != def.ID {
		t.Errorf("reassign log = %v", repo.reassignLog)
	}
	if _, ok := repo.policies[p.ID]; ok {
		t.Error("policy not deleted after force")
	}
}

func TestService_CreateRejectsEmptyName(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	for _, name := range []string{"", "   ", "\t\n"} {
		_, err := svc.Create(context.Background(), core.NewAccountID(), core.NewProductID(), policy.CreateRequest{
			Name: name,
		}, false)
		var appErr *core.AppError
		if !errors.As(err, &appErr) || appErr.Code != core.ErrValidationError {
			t.Errorf("name=%q: want validation_error, got %v", name, err)
		}
	}
}

func TestService_CreateRejectsNegativeMaxMachines(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	neg := -1
	_, err := svc.Create(context.Background(), core.NewAccountID(), core.NewProductID(), policy.CreateRequest{
		Name:        "bad",
		MaxMachines: &neg,
	}, false)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrValidationError {
		t.Errorf("want validation_error, got %v", err)
	}
}

func TestService_CreateRejectsZeroMaxSeats(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	zero := 0
	_, err := svc.Create(context.Background(), core.NewAccountID(), core.NewProductID(), policy.CreateRequest{
		Name:     "bad",
		MaxSeats: &zero,
	}, false)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrValidationError {
		t.Errorf("want validation_error, got %v", err)
	}
}

func TestService_CreateRejectsNegativeCheckoutGrace(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	_, err := svc.Create(context.Background(), core.NewAccountID(), core.NewProductID(), policy.CreateRequest{
		Name:             "bad",
		CheckoutGraceSec: -1,
	}, false)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrPolicyInvalidDuration {
		t.Errorf("want policy_invalid_duration, got %v", err)
	}
}

func TestService_CreateRejectsInvalidStrategy(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	_, err := svc.Create(context.Background(), core.NewAccountID(), core.NewProductID(), policy.CreateRequest{
		Name:               "bad",
		ExpirationStrategy: "BOGUS",
	}, false)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrPolicyInvalidStrategy {
		t.Errorf("want policy_invalid_strategy, got %v", err)
	}
}

func TestService_CreateRejectsInvalidBasis(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	_, err := svc.Create(context.Background(), core.NewAccountID(), core.NewProductID(), policy.CreateRequest{
		Name:            "bad",
		ExpirationBasis: "BOGUS",
	}, false)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrPolicyInvalidBasis {
		t.Errorf("want policy_invalid_basis, got %v", err)
	}
}

func TestService_CreateRejectsNegativeDuration(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	neg := -1
	_, err := svc.Create(context.Background(), core.NewAccountID(), core.NewProductID(), policy.CreateRequest{
		Name:            "bad",
		DurationSeconds: &neg,
	}, false)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrPolicyInvalidDuration {
		t.Errorf("want policy_invalid_duration, got %v", err)
	}
}

func TestService_CreateRejectsTTLBelowMin(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	tooSmall := 59
	_, err := svc.Create(context.Background(), core.NewAccountID(), core.NewProductID(), policy.CreateRequest{
		Name:             "bad",
		ValidationTTLSec: &tooSmall,
	}, false)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrPolicyInvalidTTL {
		t.Errorf("want policy_invalid_ttl, got %v", err)
	}
}

func TestService_CreateRejectsTTLAboveMax(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	tooBig := 2_592_001
	_, err := svc.Create(context.Background(), core.NewAccountID(), core.NewProductID(), policy.CreateRequest{
		Name:             "bad",
		ValidationTTLSec: &tooBig,
	}, false)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrPolicyInvalidTTL {
		t.Errorf("want policy_invalid_ttl, got %v", err)
	}
}

func TestService_CreateAcceptsTTLAtBounds(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	lo, hi := 60, 2_592_000
	if _, err := svc.Create(context.Background(), core.NewAccountID(), core.NewProductID(), policy.CreateRequest{
		Name:             "lo",
		ValidationTTLSec: &lo,
	}, false); err != nil {
		t.Errorf("min bound (60) rejected: %v", err)
	}
	if _, err := svc.Create(context.Background(), core.NewAccountID(), core.NewProductID(), policy.CreateRequest{
		Name:             "hi",
		ValidationTTLSec: &hi,
	}, false); err != nil {
		t.Errorf("max bound (2592000) rejected: %v", err)
	}
}

func TestService_UpdateRejectsTTLBelowMin(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	p, _ := svc.Create(context.Background(), core.NewAccountID(), core.NewProductID(), policy.CreateRequest{Name: "ok"}, false)
	bad := 30
	ttlPtrPtr := &bad
	_, err := svc.Update(context.Background(), p.ID, policy.UpdateRequest{
		ValidationTTLSec: &ttlPtrPtr,
	})
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrPolicyInvalidTTL {
		t.Errorf("want policy_invalid_ttl, got %v", err)
	}
}

func TestService_UpdateName(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	aid := core.NewAccountID()
	pid := core.NewProductID()
	p, _ := svc.CreateDefault(context.Background(), aid, pid)
	newName := "Renamed"
	updated, err := svc.Update(context.Background(), p.ID, policy.UpdateRequest{Name: &newName})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Renamed" {
		t.Errorf("Name = %s, want Renamed", updated.Name)
	}
}
