package entitlement_test

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/entitlement"
)

// ---------------------------------------------------------------------------
// fakeEntitlementRepo — implements domain.EntitlementRepository in-memory
// ---------------------------------------------------------------------------

type fakeEntitlementRepo struct {
	mu            sync.Mutex
	byID          map[core.EntitlementID]*domain.Entitlement
	byCode        map[string]core.EntitlementID // key: accountID|lower(code)
	policyAttach  map[core.PolicyID]map[core.EntitlementID]bool
	licenseAttach map[core.LicenseID]map[core.EntitlementID]bool

	// licenseToPolicyID maps license → policy so ResolveEffective can
	// compute the union. Tests pre-seed this via SetLicensePolicy.
	licenseToPolicyID map[core.LicenseID]core.PolicyID
}

func newFakeRepo() *fakeEntitlementRepo {
	return &fakeEntitlementRepo{
		byID:              map[core.EntitlementID]*domain.Entitlement{},
		byCode:            map[string]core.EntitlementID{},
		policyAttach:      map[core.PolicyID]map[core.EntitlementID]bool{},
		licenseAttach:     map[core.LicenseID]map[core.EntitlementID]bool{},
		licenseToPolicyID: map[core.LicenseID]core.PolicyID{},
	}
}

// SetLicensePolicy is a test-only helper to seed the license → policy mapping.
func (r *fakeEntitlementRepo) SetLicensePolicy(licenseID core.LicenseID, policyID core.PolicyID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.licenseToPolicyID[licenseID] = policyID
}

func codeKey(accountID core.AccountID, code string) string {
	return accountID.String() + "|" + strings.ToLower(code)
}

// -- Registry CRUD --

func (r *fakeEntitlementRepo) Create(_ context.Context, e *domain.Entitlement) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := codeKey(e.AccountID, e.Code)
	if _, exists := r.byCode[k]; exists {
		return core.NewAppError(core.ErrEntitlementDuplicateCode, "duplicate code")
	}
	r.byID[e.ID] = e
	r.byCode[k] = e.ID
	return nil
}

func (r *fakeEntitlementRepo) Get(_ context.Context, id core.EntitlementID) (*domain.Entitlement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	return e, nil
}

func (r *fakeEntitlementRepo) GetByCodes(_ context.Context, accountID core.AccountID, codes []string) ([]domain.Entitlement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var result []domain.Entitlement
	for _, c := range codes {
		if id, ok := r.byCode[codeKey(accountID, c)]; ok {
			if e, ok := r.byID[id]; ok {
				result = append(result, *e)
			}
		}
	}
	return result, nil
}

func (r *fakeEntitlementRepo) List(_ context.Context, _ core.AccountID, _ string, _ core.Cursor, _ int) ([]domain.Entitlement, bool, error) {
	return nil, false, nil
}

func (r *fakeEntitlementRepo) Update(_ context.Context, e *domain.Entitlement) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[e.ID]; !ok {
		return core.NewAppError(core.ErrEntitlementNotFound, "not found")
	}
	r.byID[e.ID] = e
	return nil
}

func (r *fakeEntitlementRepo) Delete(_ context.Context, id core.EntitlementID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.byID[id]
	if !ok {
		return core.NewAppError(core.ErrEntitlementNotFound, "not found")
	}
	// Check FK constraints: refuse if attached to any policy or license.
	for _, entIDs := range r.policyAttach {
		if entIDs[id] {
			return core.NewAppError(core.ErrEntitlementInUse, "entitlement is attached to a policy")
		}
	}
	for _, entIDs := range r.licenseAttach {
		if entIDs[id] {
			return core.NewAppError(core.ErrEntitlementInUse, "entitlement is attached to a license")
		}
	}
	delete(r.byID, id)
	delete(r.byCode, codeKey(e.AccountID, e.Code))
	return nil
}

// -- Policy attachments --

func (r *fakeEntitlementRepo) AttachToPolicy(_ context.Context, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.policyAttach[policyID] == nil {
		r.policyAttach[policyID] = map[core.EntitlementID]bool{}
	}
	for _, id := range entitlementIDs {
		r.policyAttach[policyID][id] = true
	}
	return nil
}

func (r *fakeEntitlementRepo) DetachFromPolicy(_ context.Context, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.policyAttach[policyID]
	if m == nil {
		return nil
	}
	for _, id := range entitlementIDs {
		delete(m, id)
	}
	return nil
}

func (r *fakeEntitlementRepo) ReplacePolicyAttachments(_ context.Context, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	newSet := map[core.EntitlementID]bool{}
	for _, id := range entitlementIDs {
		newSet[id] = true
	}
	r.policyAttach[policyID] = newSet
	return nil
}

func (r *fakeEntitlementRepo) ListPolicyCodes(_ context.Context, policyID core.PolicyID) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entIDs := r.policyAttach[policyID]
	var codes []string
	for id := range entIDs {
		if e, ok := r.byID[id]; ok {
			codes = append(codes, e.Code)
		}
	}
	sort.Strings(codes)
	return codes, nil
}

// -- License attachments --

func (r *fakeEntitlementRepo) AttachToLicense(_ context.Context, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.licenseAttach[licenseID] == nil {
		r.licenseAttach[licenseID] = map[core.EntitlementID]bool{}
	}
	for _, id := range entitlementIDs {
		r.licenseAttach[licenseID][id] = true
	}
	return nil
}

func (r *fakeEntitlementRepo) DetachFromLicense(_ context.Context, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.licenseAttach[licenseID]
	if m == nil {
		return nil
	}
	for _, id := range entitlementIDs {
		delete(m, id)
	}
	return nil
}

func (r *fakeEntitlementRepo) ReplaceLicenseAttachments(_ context.Context, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	newSet := map[core.EntitlementID]bool{}
	for _, id := range entitlementIDs {
		newSet[id] = true
	}
	r.licenseAttach[licenseID] = newSet
	return nil
}

func (r *fakeEntitlementRepo) ListLicenseCodes(_ context.Context, licenseID core.LicenseID) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entIDs := r.licenseAttach[licenseID]
	var codes []string
	for id := range entIDs {
		if e, ok := r.byID[id]; ok {
			codes = append(codes, e.Code)
		}
	}
	sort.Strings(codes)
	return codes, nil
}

// -- ResolveEffective --

func (r *fakeEntitlementRepo) ResolveEffective(_ context.Context, licenseID core.LicenseID) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := map[string]bool{}

	// Policy entitlements (via license → policy mapping).
	if policyID, ok := r.licenseToPolicyID[licenseID]; ok {
		for id := range r.policyAttach[policyID] {
			if e, ok := r.byID[id]; ok {
				seen[e.Code] = true
			}
		}
	}

	// License-direct entitlements.
	for id := range r.licenseAttach[licenseID] {
		if e, ok := r.byID[id]; ok {
			seen[e.Code] = true
		}
	}

	codes := make([]string, 0, len(seen))
	for c := range seen {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	return codes, nil
}

// Compile-time check.
var _ domain.EntitlementRepository = (*fakeEntitlementRepo)(nil)

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCreate_HappyPath(t *testing.T) {
	repo := newFakeRepo()
	svc := entitlement.NewService(repo)
	acc := core.NewAccountID()

	e, err := svc.Create(context.Background(), acc, entitlement.CreateRequest{
		Code: "OFFLINE_SUPPORT",
		Name: "Offline Support",
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.Code != "OFFLINE_SUPPORT" {
		t.Errorf("code = %q, want OFFLINE_SUPPORT", e.Code)
	}
	if e.Name != "Offline Support" {
		t.Errorf("name = %q, want Offline Support", e.Name)
	}

	// Round-trip via Get.
	got, err := svc.Get(context.Background(), e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Code != "OFFLINE_SUPPORT" {
		t.Errorf("round-trip code = %q", got.Code)
	}
}

func TestCreate_InvalidCode(t *testing.T) {
	svc := entitlement.NewService(newFakeRepo())
	_, err := svc.Create(context.Background(), core.NewAccountID(), entitlement.CreateRequest{
		Code: "lowercase_code",
		Name: "Bad",
	})
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrEntitlementInvalidCode {
		t.Errorf("want ErrEntitlementInvalidCode, got %v", err)
	}
}

func TestCreate_DuplicateCode(t *testing.T) {
	repo := newFakeRepo()
	svc := entitlement.NewService(repo)
	acc := core.NewAccountID()

	_, err := svc.Create(context.Background(), acc, entitlement.CreateRequest{
		Code: "FEATURE_A",
		Name: "Feature A",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.Create(context.Background(), acc, entitlement.CreateRequest{
		Code: "FEATURE_A",
		Name: "Feature A duplicate",
	})
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrEntitlementDuplicateCode {
		t.Errorf("want ErrEntitlementDuplicateCode, got %v", err)
	}
}

func TestGet_NotFound(t *testing.T) {
	svc := entitlement.NewService(newFakeRepo())
	_, err := svc.Get(context.Background(), core.NewEntitlementID())
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrEntitlementNotFound {
		t.Errorf("want ErrEntitlementNotFound, got %v", err)
	}
}

func TestUpdate_CodeImmutable(t *testing.T) {
	repo := newFakeRepo()
	svc := entitlement.NewService(repo)
	acc := core.NewAccountID()

	e, err := svc.Create(context.Background(), acc, entitlement.CreateRequest{
		Code: "ORIGINAL",
		Name: "Original",
	})
	if err != nil {
		t.Fatal(err)
	}

	newCode := "CHANGED"
	_, err = svc.Update(context.Background(), e.ID, entitlement.UpdateRequest{
		Code: &newCode,
	})
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrEntitlementCodeImmutable {
		t.Errorf("want ErrEntitlementCodeImmutable, got %v", err)
	}
}

func TestUpdate_NameOnly(t *testing.T) {
	repo := newFakeRepo()
	svc := entitlement.NewService(repo)
	acc := core.NewAccountID()

	e, err := svc.Create(context.Background(), acc, entitlement.CreateRequest{
		Code: "FEATURE_X",
		Name: "Old Name",
	})
	if err != nil {
		t.Fatal(err)
	}

	newName := "New Name"
	updated, err := svc.Update(context.Background(), e.ID, entitlement.UpdateRequest{
		Name: &newName,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "New Name" {
		t.Errorf("name = %q, want New Name", updated.Name)
	}
	if updated.Code != "FEATURE_X" {
		t.Errorf("code changed unexpectedly: %q", updated.Code)
	}
}

func TestDelete_InUse(t *testing.T) {
	repo := newFakeRepo()
	svc := entitlement.NewService(repo)
	acc := core.NewAccountID()

	e, err := svc.Create(context.Background(), acc, entitlement.CreateRequest{
		Code: "ATTACHED",
		Name: "Attached",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Attach to a policy.
	policyID := core.NewPolicyID()
	if err := svc.AttachToPolicy(context.Background(), policyID, []string{"ATTACHED"}, acc); err != nil {
		t.Fatal(err)
	}

	// Delete should fail.
	err = svc.Delete(context.Background(), e.ID)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrEntitlementInUse {
		t.Errorf("want ErrEntitlementInUse, got %v", err)
	}
}

func TestDelete_Success(t *testing.T) {
	repo := newFakeRepo()
	svc := entitlement.NewService(repo)
	acc := core.NewAccountID()

	e, err := svc.Create(context.Background(), acc, entitlement.CreateRequest{
		Code: "DELETABLE",
		Name: "Deletable",
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.Delete(context.Background(), e.ID); err != nil {
		t.Fatal(err)
	}

	// Verify gone.
	_, err = svc.Get(context.Background(), e.ID)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrEntitlementNotFound {
		t.Errorf("expected not found after delete, got %v", err)
	}
}

func TestAttachToPolicy_UnknownCode(t *testing.T) {
	svc := entitlement.NewService(newFakeRepo())
	acc := core.NewAccountID()
	policyID := core.NewPolicyID()

	err := svc.AttachToPolicy(context.Background(), policyID, []string{"NONEXISTENT"}, acc)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrEntitlementNotFound {
		t.Errorf("want ErrEntitlementNotFound, got %v", err)
	}
}

func TestAttachToPolicy_Idempotent(t *testing.T) {
	repo := newFakeRepo()
	svc := entitlement.NewService(repo)
	acc := core.NewAccountID()

	_, err := svc.Create(context.Background(), acc, entitlement.CreateRequest{
		Code: "FEATURE_A",
		Name: "Feature A",
	})
	if err != nil {
		t.Fatal(err)
	}

	policyID := core.NewPolicyID()

	// Attach twice — should not error.
	if err := svc.AttachToPolicy(context.Background(), policyID, []string{"FEATURE_A"}, acc); err != nil {
		t.Fatal(err)
	}
	if err := svc.AttachToPolicy(context.Background(), policyID, []string{"FEATURE_A"}, acc); err != nil {
		t.Fatal(err)
	}

	codes, err := svc.ListPolicyCodes(context.Background(), policyID)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 1 || codes[0] != "FEATURE_A" {
		t.Errorf("expected [FEATURE_A], got %v", codes)
	}
}

func TestResolveEffective_Union(t *testing.T) {
	repo := newFakeRepo()
	svc := entitlement.NewService(repo)
	acc := core.NewAccountID()

	// Create two entitlements.
	if _, err := svc.Create(context.Background(), acc, entitlement.CreateRequest{Code: "ALPHA", Name: "Alpha"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(context.Background(), acc, entitlement.CreateRequest{Code: "BRAVO", Name: "Bravo"}); err != nil {
		t.Fatal(err)
	}

	policyID := core.NewPolicyID()
	licenseID := core.NewLicenseID()

	// Wire license → policy in the fake.
	repo.SetLicensePolicy(licenseID, policyID)

	// Attach ALPHA to policy, BRAVO to license.
	if err := svc.AttachToPolicy(context.Background(), policyID, []string{"ALPHA"}, acc); err != nil {
		t.Fatal(err)
	}
	if err := svc.AttachToLicense(context.Background(), licenseID, []string{"BRAVO"}, acc); err != nil {
		t.Fatal(err)
	}

	codes, err := svc.ResolveEffective(context.Background(), licenseID)
	if err != nil {
		t.Fatal(err)
	}

	expected := []string{"ALPHA", "BRAVO"}
	if len(codes) != len(expected) {
		t.Fatalf("effective = %v, want %v", codes, expected)
	}
	for i, c := range codes {
		if c != expected[i] {
			t.Errorf("effective[%d] = %q, want %q", i, c, expected[i])
		}
	}
}

func TestThreeSetResponse(t *testing.T) {
	repo := newFakeRepo()
	svc := entitlement.NewService(repo)
	acc := core.NewAccountID()

	// Create entitlements.
	if _, err := svc.Create(context.Background(), acc, entitlement.CreateRequest{Code: "ALPHA", Name: "Alpha"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(context.Background(), acc, entitlement.CreateRequest{Code: "BRAVO", Name: "Bravo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(context.Background(), acc, entitlement.CreateRequest{Code: "CHARLIE", Name: "Charlie"}); err != nil {
		t.Fatal(err)
	}

	policyID := core.NewPolicyID()
	licenseID := core.NewLicenseID()
	repo.SetLicensePolicy(licenseID, policyID)

	// Attach ALPHA + CHARLIE to policy, BRAVO to license.
	if err := svc.AttachToPolicy(context.Background(), policyID, []string{"ALPHA", "CHARLIE"}, acc); err != nil {
		t.Fatal(err)
	}
	if err := svc.AttachToLicense(context.Background(), licenseID, []string{"BRAVO"}, acc); err != nil {
		t.Fatal(err)
	}

	sets, err := svc.ThreeSetResponse(context.Background(), licenseID, policyID)
	if err != nil {
		t.Fatal(err)
	}

	// Policy should be sorted.
	wantPolicy := []string{"ALPHA", "CHARLIE"}
	if !stringSliceEqual(sets.Policy, wantPolicy) {
		t.Errorf("policy = %v, want %v", sets.Policy, wantPolicy)
	}

	wantLicense := []string{"BRAVO"}
	if !stringSliceEqual(sets.License, wantLicense) {
		t.Errorf("license = %v, want %v", sets.License, wantLicense)
	}

	wantEffective := []string{"ALPHA", "BRAVO", "CHARLIE"}
	if !stringSliceEqual(sets.Effective, wantEffective) {
		t.Errorf("effective = %v, want %v", sets.Effective, wantEffective)
	}
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
