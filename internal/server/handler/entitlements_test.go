package handler

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/entitlement"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// --- Minimal fakes for the entitlement handler product-scope gate tests.
// The gate fires inside the WithTargetAccount closure AFTER the
// policy/license is loaded but BEFORE the entitlement service touches
// any data. We only need the policy/license repo to return a row whose
// ProductID we control; the entitlement repo is never invoked because
// the gate aborts the closure before svc.Attach/Detach/Replace runs.

type fakeTxManagerEnt struct{}

func (m *fakeTxManagerEnt) WithTargetAccount(ctx context.Context, _ core.AccountID, _ core.Environment, fn func(context.Context) error) error {
	return fn(ctx)
}

func (m *fakeTxManagerEnt) WithTx(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

func (m *fakeTxManagerEnt) WithSystemContext(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

type fakePolicyRepoEnt struct {
	policy *domain.Policy
}

func (r *fakePolicyRepoEnt) Create(_ context.Context, _ *domain.Policy) error { return nil }
func (r *fakePolicyRepoEnt) Get(_ context.Context, _ core.PolicyID) (*domain.Policy, error) {
	return r.policy, nil
}
func (r *fakePolicyRepoEnt) GetByProduct(_ context.Context, _ core.ProductID, _ core.Cursor, _ int) ([]domain.Policy, bool, error) {
	return nil, false, nil
}
func (r *fakePolicyRepoEnt) GetDefaultForProduct(_ context.Context, _ core.ProductID) (*domain.Policy, error) {
	return nil, nil
}
func (r *fakePolicyRepoEnt) Update(_ context.Context, _ *domain.Policy) error { return nil }
func (r *fakePolicyRepoEnt) Delete(_ context.Context, _ core.PolicyID) error  { return nil }
func (r *fakePolicyRepoEnt) SetDefault(_ context.Context, _ core.ProductID, _ core.PolicyID) error {
	return nil
}
func (r *fakePolicyRepoEnt) ReassignLicensesFromPolicy(_ context.Context, _, _ core.PolicyID) (int, error) {
	return 0, nil
}
func (r *fakePolicyRepoEnt) CountReferencingLicenses(_ context.Context, _ core.PolicyID) (int, error) {
	return 0, nil
}

type fakeLicenseRepoEnt struct {
	license *domain.License
}

func (r *fakeLicenseRepoEnt) Create(_ context.Context, _ *domain.License) error { return nil }
func (r *fakeLicenseRepoEnt) BulkCreate(_ context.Context, _ []*domain.License) error {
	return nil
}
func (r *fakeLicenseRepoEnt) GetByID(_ context.Context, _ core.LicenseID) (*domain.License, error) {
	return r.license, nil
}
func (r *fakeLicenseRepoEnt) GetByIDForUpdate(_ context.Context, _ core.LicenseID) (*domain.License, error) {
	return r.license, nil
}
func (r *fakeLicenseRepoEnt) GetByKeyHash(_ context.Context, _ string) (*domain.License, error) {
	return nil, nil
}
func (r *fakeLicenseRepoEnt) List(_ context.Context, _ domain.LicenseListFilters, _ core.Cursor, _ int) ([]domain.License, bool, error) {
	return nil, false, nil
}
func (r *fakeLicenseRepoEnt) ListByProduct(_ context.Context, _ core.ProductID, _ domain.LicenseListFilters, _ core.Cursor, _ int) ([]domain.License, bool, error) {
	return nil, false, nil
}
func (r *fakeLicenseRepoEnt) Update(_ context.Context, _ *domain.License) error { return nil }
func (r *fakeLicenseRepoEnt) UpdateStatus(_ context.Context, _ core.LicenseID, _, _ core.LicenseStatus) (time.Time, error) {
	return time.Time{}, nil
}
func (r *fakeLicenseRepoEnt) CountByProduct(_ context.Context, _ core.ProductID) (int, error) {
	return 0, nil
}
func (r *fakeLicenseRepoEnt) CountsByProductStatus(_ context.Context, _ core.ProductID) (domain.LicenseStatusCounts, error) {
	return domain.LicenseStatusCounts{}, nil
}
func (r *fakeLicenseRepoEnt) BulkRevokeByProduct(_ context.Context, _ core.ProductID) (int, error) {
	return 0, nil
}
func (r *fakeLicenseRepoEnt) HasBlocking(_ context.Context) (bool, error) { return false, nil }
func (r *fakeLicenseRepoEnt) ExpireActive(_ context.Context) ([]domain.License, error) {
	return nil, nil
}

// fakeEntitlementRepoEnt is a no-op stub. The gate tests assert the
// repo is NEVER reached; if any method here is called the test fails
// because the call would surface as a nil dereference downstream.
type fakeEntitlementRepoEnt struct{}

func (r *fakeEntitlementRepoEnt) Create(_ context.Context, _ *domain.Entitlement) error {
	return nil
}
func (r *fakeEntitlementRepoEnt) Get(_ context.Context, _ core.EntitlementID) (*domain.Entitlement, error) {
	return nil, nil
}
func (r *fakeEntitlementRepoEnt) GetByCodes(_ context.Context, _ core.AccountID, _ []string) ([]domain.Entitlement, error) {
	return nil, nil
}
func (r *fakeEntitlementRepoEnt) List(_ context.Context, _ core.AccountID, _ string, _ core.Cursor, _ int) ([]domain.Entitlement, bool, error) {
	return nil, false, nil
}
func (r *fakeEntitlementRepoEnt) Update(_ context.Context, _ *domain.Entitlement) error {
	return nil
}
func (r *fakeEntitlementRepoEnt) Delete(_ context.Context, _ core.EntitlementID) error {
	return nil
}
func (r *fakeEntitlementRepoEnt) AttachToPolicy(_ context.Context, _ core.PolicyID, _ []core.EntitlementID) error {
	return nil
}
func (r *fakeEntitlementRepoEnt) DetachFromPolicy(_ context.Context, _ core.PolicyID, _ []core.EntitlementID) error {
	return nil
}
func (r *fakeEntitlementRepoEnt) ReplacePolicyAttachments(_ context.Context, _ core.PolicyID, _ []core.EntitlementID) error {
	return nil
}
func (r *fakeEntitlementRepoEnt) ListPolicyCodes(_ context.Context, _ core.PolicyID) ([]string, error) {
	return nil, nil
}
func (r *fakeEntitlementRepoEnt) AttachToLicense(_ context.Context, _ core.LicenseID, _ []core.EntitlementID) error {
	return nil
}
func (r *fakeEntitlementRepoEnt) DetachFromLicense(_ context.Context, _ core.LicenseID, _ []core.EntitlementID) error {
	return nil
}
func (r *fakeEntitlementRepoEnt) ReplaceLicenseAttachments(_ context.Context, _ core.LicenseID, _ []core.EntitlementID) error {
	return nil
}
func (r *fakeEntitlementRepoEnt) ListLicenseCodes(_ context.Context, _ core.LicenseID) ([]string, error) {
	return nil, nil
}
func (r *fakeEntitlementRepoEnt) ResolveEffective(_ context.Context, _ core.LicenseID) ([]string, error) {
	return nil, nil
}

// errorAppHandler is the standard test ErrorHandler — unwraps
// *core.AppError to its HTTP status + JSON body so the test can
// assert on the typed error code.
func newAppForEntTest() *fiber.App {
	return fiber.New(fiber.Config{
		ErrorHandler: func(c fiber.Ctx, err error) error {
			var ae *core.AppError
			if errors.As(err, &ae) {
				return c.Status(ae.HTTPStatus()).JSON(ae)
			}
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		},
	})
}

// injectAuthEnt seeds the AuthContext on BOTH c.Locals and the
// request's Go context — mirrors what RequireAuth does in production.
// The product-scope gate inside WithTargetAccount reads from the Go
// context (via middleware.AuthFromGoContext); a Locals-only seeding
// would silently fail to fire the gate.
func injectAuthEnt(auth *middleware.AuthContext) fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Locals("auth", auth)
		c.SetContext(middleware.WithAuthForTest(c.Context(), auth))
		return c.Next()
	}
}

// adminRoleEnt grants every permission needed by the entitlement
// handlers — bypasses RBAC so the tests narrowly exercise the
// product-scope gate.
func adminRoleEnt() *domain.Role {
	return &domain.Role{
		Slug: "admin",
		Permissions: []string{
			"policy:read", "policy:write",
			"license:read", "license:update",
			"entitlement:read", "entitlement:write",
		},
	}
}

func TestEntitlementHandler_ProductScopedKey_MismatchRejected_OnPolicyEntitlements(t *testing.T) {
	// A product-scoped API key bound to product B must not be able to
	// list entitlements on a policy that belongs to product A.
	policyProduct := core.NewProductID() // product A
	keyProduct := core.NewProductID()    // product B (different)

	policyRepo := &fakePolicyRepoEnt{
		policy: &domain.Policy{
			ID:        core.NewPolicyID(),
			AccountID: core.NewAccountID(),
			ProductID: policyProduct,
		},
	}
	licenseRepo := &fakeLicenseRepoEnt{}
	entRepo := &fakeEntitlementRepoEnt{}
	svc := entitlement.NewService(entRepo)
	tx := &fakeTxManagerEnt{}
	h := NewEntitlementHandler(tx, svc, licenseRepo, policyRepo)

	auth := &middleware.AuthContext{
		ActorKind:       middleware.ActorKindAPIKey,
		ActingAccountID: core.NewAccountID(),
		TargetAccountID: core.NewAccountID(),
		Environment:     core.EnvironmentLive,
		APIKeyScope:     core.APIKeyScopeProduct,
		APIKeyProductID: &keyProduct,
		Role:            adminRoleEnt(),
	}

	app := newAppForEntTest()
	app.Get("/policies/:id/entitlements", injectAuthEnt(auth), h.ListPolicyEntitlements)

	req := httptest.NewRequest("GET", "/policies/"+core.NewPolicyID().String()+"/entitlements", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, 403, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "api_key_scope_mismatch",
		"product-scope mismatch must surface as ErrAPIKeyScopeMismatch even after the policy is loaded")
}

func TestEntitlementHandler_ProductScopedKey_MismatchRejected_OnLicenseEntitlements(t *testing.T) {
	// A product-scoped API key bound to product B must not be able to
	// list/attach/detach entitlements on a license that belongs to
	// product A. We exercise the AttachLicenseEntitlements path because
	// it represents the write surface; the gate placement is identical
	// across all four license-entitlement handlers.
	licenseProduct := core.NewProductID() // product A
	keyProduct := core.NewProductID()     // product B (different)

	policyRepo := &fakePolicyRepoEnt{}
	licenseRepo := &fakeLicenseRepoEnt{
		license: &domain.License{
			ID:        core.NewLicenseID(),
			AccountID: core.NewAccountID(),
			ProductID: licenseProduct,
			PolicyID:  core.NewPolicyID(),
		},
	}
	entRepo := &fakeEntitlementRepoEnt{}
	svc := entitlement.NewService(entRepo)
	tx := &fakeTxManagerEnt{}
	h := NewEntitlementHandler(tx, svc, licenseRepo, policyRepo)

	auth := &middleware.AuthContext{
		ActorKind:       middleware.ActorKindAPIKey,
		ActingAccountID: core.NewAccountID(),
		TargetAccountID: core.NewAccountID(),
		Environment:     core.EnvironmentLive,
		APIKeyScope:     core.APIKeyScopeProduct,
		APIKeyProductID: &keyProduct,
		Role:            adminRoleEnt(),
	}

	app := newAppForEntTest()
	app.Post("/licenses/:id/entitlements", injectAuthEnt(auth), h.AttachLicenseEntitlements)

	req := httptest.NewRequest("POST", "/licenses/"+core.NewLicenseID().String()+"/entitlements",
		strings.NewReader(`{"codes":["FEATURE_A"]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, 403, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "api_key_scope_mismatch",
		"product-scope mismatch must surface as ErrAPIKeyScopeMismatch even after the license is loaded")
}
