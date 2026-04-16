// Package entitlement owns the entitlements registry — named feature/
// capability records that attach to policies (inherited by all licenses)
// and optionally per-license (add-only). The effective set is the sorted
// union of policy + license entitlements.
//
// Service methods are pure business logic — they do NOT open their own
// transactions. Callers (HTTP handlers OR other services like
// licensing.Service) are responsible for tx discipline. This mirrors
// the customer.Service pattern.
package entitlement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Service owns entitlement registry CRUD plus attach/detach operations
// on policies and licenses. Pure — no internal tx.
type Service struct {
	repo domain.EntitlementRepository
}

// NewService constructs an entitlement service backed by the given repository.
func NewService(repo domain.EntitlementRepository) *Service {
	return &Service{repo: repo}
}

// CreateRequest is the public create shape.
type CreateRequest struct {
	Code     string          `json:"code"`
	Name     string          `json:"name"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// UpdateRequest is the partial update shape. Omitted fields are unchanged.
type UpdateRequest struct {
	Code     *string          `json:"code,omitempty"`
	Name     *string          `json:"name,omitempty"`
	Metadata *json.RawMessage `json:"metadata,omitempty"`
}

// EntitlementSets holds the three-set response for a license's entitlements.
type EntitlementSets struct {
	Policy    []string `json:"policy"`
	License   []string `json:"license"`
	Effective []string `json:"effective"`
}

// Create validates the code format, checks for duplicates, and inserts
// a new entitlement into the registry.
func (s *Service) Create(ctx context.Context, accountID core.AccountID, req CreateRequest) (*domain.Entitlement, error) {
	if err := ValidateCode(req.Code); err != nil {
		return nil, err
	}

	// Check for duplicate code within this account.
	existing, err := s.repo.GetByCodes(ctx, accountID, []string{req.Code})
	if err != nil {
		return nil, err
	}
	if len(existing) > 0 {
		return nil, core.NewAppError(core.ErrEntitlementDuplicateCode, "entitlement code already exists: "+req.Code)
	}

	now := time.Now().UTC()
	e := &domain.Entitlement{
		ID:        core.NewEntitlementID(),
		AccountID: accountID,
		Code:      req.Code,
		Name:      req.Name,
		Metadata:  req.Metadata,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.repo.Create(ctx, e); err != nil {
		return nil, err
	}
	return e, nil
}

// Get fetches an entitlement by ID; translates repo nil to ErrEntitlementNotFound.
func (s *Service) Get(ctx context.Context, id core.EntitlementID) (*domain.Entitlement, error) {
	e, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, core.NewAppError(core.ErrEntitlementNotFound, "entitlement not found")
	}
	return e, nil
}

// List returns a paginated entitlement list for the account, optionally
// filtered by code prefix.
func (s *Service) List(ctx context.Context, accountID core.AccountID, codePrefix string, cursor core.Cursor, limit int) ([]domain.Entitlement, bool, error) {
	return s.repo.List(ctx, accountID, codePrefix, cursor, limit)
}

// Update mutates name and/or metadata. Code is immutable after creation.
func (s *Service) Update(ctx context.Context, id core.EntitlementID, req UpdateRequest) (*domain.Entitlement, error) {
	e, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	// Reject code changes.
	if req.Code != nil && *req.Code != e.Code {
		return nil, core.NewAppError(core.ErrEntitlementCodeImmutable, "entitlement code cannot be changed after creation")
	}

	if req.Name != nil {
		e.Name = *req.Name
	}
	if req.Metadata != nil {
		e.Metadata = *req.Metadata
	}
	e.UpdatedAt = time.Now().UTC()

	if err := s.repo.Update(ctx, e); err != nil {
		return nil, err
	}
	return e, nil
}

// Delete removes an entitlement from the registry. Translates FK
// constraint violations from policy_entitlements / license_entitlements
// into ErrEntitlementInUse.
func (s *Service) Delete(ctx context.Context, id core.EntitlementID) error {
	if _, err := s.Get(ctx, id); err != nil {
		return err
	}
	err := s.repo.Delete(ctx, id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return core.NewAppError(core.ErrEntitlementInUse, "entitlement is attached to a policy or license")
		}
	}
	return err
}

// ResolveCodeToIDs looks up entitlement codes within an account and
// returns their IDs. Returns ErrEntitlementNotFound if any code is unknown.
func (s *Service) ResolveCodeToIDs(ctx context.Context, accountID core.AccountID, codes []string) ([]core.EntitlementID, error) {
	rows, err := s.repo.GetByCodes(ctx, accountID, codes)
	if err != nil {
		return nil, err
	}
	if len(rows) != len(codes) {
		// Find which codes are missing for the error message.
		found := make(map[string]bool, len(rows))
		for _, r := range rows {
			found[strings.ToUpper(r.Code)] = true
		}
		var missing []string
		for _, c := range codes {
			if !found[strings.ToUpper(c)] {
				missing = append(missing, c)
			}
		}
		return nil, core.NewAppError(core.ErrEntitlementNotFound,
			fmt.Sprintf("unknown entitlement code(s): %s", strings.Join(missing, ", ")))
	}
	ids := make([]core.EntitlementID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	return ids, nil
}

// AttachToPolicy resolves codes to IDs and attaches them to a policy.
func (s *Service) AttachToPolicy(ctx context.Context, policyID core.PolicyID, codes []string, accountID core.AccountID) error {
	ids, err := s.ResolveCodeToIDs(ctx, accountID, codes)
	if err != nil {
		return err
	}
	return s.repo.AttachToPolicy(ctx, policyID, ids)
}

// DetachFromPolicy resolves a single code to an ID and detaches it from a policy.
func (s *Service) DetachFromPolicy(ctx context.Context, policyID core.PolicyID, code string, accountID core.AccountID) error {
	ids, err := s.ResolveCodeToIDs(ctx, accountID, []string{code})
	if err != nil {
		return err
	}
	return s.repo.DetachFromPolicy(ctx, policyID, ids)
}

// ReplacePolicyAttachments resolves codes to IDs and replaces all policy attachments.
func (s *Service) ReplacePolicyAttachments(ctx context.Context, policyID core.PolicyID, codes []string, accountID core.AccountID) error {
	if len(codes) == 0 {
		return s.repo.ReplacePolicyAttachments(ctx, policyID, nil)
	}
	ids, err := s.ResolveCodeToIDs(ctx, accountID, codes)
	if err != nil {
		return err
	}
	return s.repo.ReplacePolicyAttachments(ctx, policyID, ids)
}

// AttachToLicense resolves codes to IDs and attaches them to a license.
func (s *Service) AttachToLicense(ctx context.Context, licenseID core.LicenseID, codes []string, accountID core.AccountID) error {
	ids, err := s.ResolveCodeToIDs(ctx, accountID, codes)
	if err != nil {
		return err
	}
	return s.repo.AttachToLicense(ctx, licenseID, ids)
}

// DetachFromLicense resolves a single code to an ID and detaches it from a license.
func (s *Service) DetachFromLicense(ctx context.Context, licenseID core.LicenseID, code string, accountID core.AccountID) error {
	ids, err := s.ResolveCodeToIDs(ctx, accountID, []string{code})
	if err != nil {
		return err
	}
	return s.repo.DetachFromLicense(ctx, licenseID, ids)
}

// ReplaceLicenseAttachments resolves codes to IDs and replaces all license attachments.
func (s *Service) ReplaceLicenseAttachments(ctx context.Context, licenseID core.LicenseID, codes []string, accountID core.AccountID) error {
	if len(codes) == 0 {
		return s.repo.ReplaceLicenseAttachments(ctx, licenseID, nil)
	}
	ids, err := s.ResolveCodeToIDs(ctx, accountID, codes)
	if err != nil {
		return err
	}
	return s.repo.ReplaceLicenseAttachments(ctx, licenseID, ids)
}

// ListPolicyCodes returns sorted entitlement codes attached to a policy.
func (s *Service) ListPolicyCodes(ctx context.Context, policyID core.PolicyID) ([]string, error) {
	return s.repo.ListPolicyCodes(ctx, policyID)
}

// ListLicenseCodes returns sorted entitlement codes attached directly to a license.
func (s *Service) ListLicenseCodes(ctx context.Context, licenseID core.LicenseID) ([]string, error) {
	return s.repo.ListLicenseCodes(ctx, licenseID)
}

// ResolveEffective returns the effective entitlement set for a license
// (sorted union of policy + license codes). Delegates to the repo's
// single-query UNION implementation.
func (s *Service) ResolveEffective(ctx context.Context, licenseID core.LicenseID) ([]string, error) {
	return s.repo.ResolveEffective(ctx, licenseID)
}

// ThreeSetResponse returns the policy, license, and effective (sorted union)
// entitlement code sets for a license. The effective set is computed in Go
// from the policy and license slices.
func (s *Service) ThreeSetResponse(ctx context.Context, licenseID core.LicenseID, policyID core.PolicyID) (EntitlementSets, error) {
	policyCodes, err := s.repo.ListPolicyCodes(ctx, policyID)
	if err != nil {
		return EntitlementSets{}, err
	}
	licenseCodes, err := s.repo.ListLicenseCodes(ctx, licenseID)
	if err != nil {
		return EntitlementSets{}, err
	}

	// Compute effective as sorted deduplicated union.
	seen := make(map[string]bool, len(policyCodes)+len(licenseCodes))
	for _, c := range policyCodes {
		seen[c] = true
	}
	for _, c := range licenseCodes {
		seen[c] = true
	}
	effective := make([]string, 0, len(seen))
	for c := range seen {
		effective = append(effective, c)
	}
	sort.Strings(effective)

	if policyCodes == nil {
		policyCodes = []string{}
	}
	if licenseCodes == nil {
		licenseCodes = []string{}
	}

	return EntitlementSets{
		Policy:    policyCodes,
		License:   licenseCodes,
		Effective: effective,
	}, nil
}
