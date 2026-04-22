package policy

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Service owns policy CRUD + default-promotion + force-delete reassignment.
// Tx management is handled by callers (handlers open WithTargetAccount).
type Service struct {
	repo domain.PolicyRepository
}

func NewService(repo domain.PolicyRepository) *Service {
	return &Service{repo: repo}
}

// CreateRequest is the public create shape. Nil fields for nullable
// numerics fall back to type-specific defaults.
type CreateRequest struct {
	Name                      string                         `json:"name"`
	DurationSeconds           *int                           `json:"duration_seconds,omitempty"`
	ExpirationStrategy        core.ExpirationStrategy        `json:"expiration_strategy,omitempty"`
	ExpirationBasis           core.ExpirationBasis           `json:"expiration_basis,omitempty"`
	MaxMachines               *int                           `json:"max_machines,omitempty"`
	MaxSeats                  *int                           `json:"max_seats,omitempty"`
	ValidationTTLSec          *int                           `json:"validation_ttl_sec,omitempty"`
	Floating                  bool                           `json:"floating,omitempty"`
	Strict                    bool                           `json:"strict,omitempty"`
	RequireCheckout           bool                           `json:"require_checkout,omitempty"`
	CheckoutIntervalSec       int                            `json:"checkout_interval_sec,omitempty"`
	MaxCheckoutDurationSec    int                            `json:"max_checkout_duration_sec,omitempty"`
	CheckoutGraceSec          int                            `json:"checkout_grace_sec,omitempty"`
	ComponentMatchingStrategy core.ComponentMatchingStrategy `json:"component_matching_strategy,omitempty"`
	Metadata                  json.RawMessage                `json:"metadata,omitempty"`
}

// UpdateRequest is the partial-update shape; non-nil fields are applied.
type UpdateRequest struct {
	Name                      *string                         `json:"name,omitempty"`
	DurationSeconds           **int                           `json:"duration_seconds,omitempty"`
	ExpirationStrategy        *core.ExpirationStrategy        `json:"expiration_strategy,omitempty"`
	ExpirationBasis           *core.ExpirationBasis           `json:"expiration_basis,omitempty"`
	MaxMachines               **int                           `json:"max_machines,omitempty"`
	MaxSeats                  **int                           `json:"max_seats,omitempty"`
	ValidationTTLSec          **int                           `json:"validation_ttl_sec,omitempty"`
	Floating                  *bool                           `json:"floating,omitempty"`
	Strict                    *bool                           `json:"strict,omitempty"`
	RequireCheckout           *bool                           `json:"require_checkout,omitempty"`
	CheckoutIntervalSec       *int                            `json:"checkout_interval_sec,omitempty"`
	MaxCheckoutDurationSec    *int                            `json:"max_checkout_duration_sec,omitempty"`
	CheckoutGraceSec          *int                            `json:"checkout_grace_sec,omitempty"`
	ComponentMatchingStrategy *core.ComponentMatchingStrategy `json:"component_matching_strategy,omitempty"`
	Metadata                  *json.RawMessage                `json:"metadata,omitempty"`
}

// Create makes a new policy under the given product. Caller is responsible
// for opening a WithTargetAccount transaction. Validation is strict: unknown
// enum values are rejected.
func (s *Service) Create(ctx context.Context, accountID core.AccountID, productID core.ProductID, req CreateRequest, isDefault bool) (*domain.Policy, error) {
	if err := validateCreate(&req); err != nil {
		return nil, err
	}
	applyCreateDefaults(&req)

	now := time.Now().UTC()
	p := &domain.Policy{
		ID:                        core.NewPolicyID(),
		AccountID:                 accountID,
		ProductID:                 productID,
		Name:                      req.Name,
		IsDefault:                 isDefault,
		DurationSeconds:           req.DurationSeconds,
		ExpirationStrategy:        req.ExpirationStrategy,
		ExpirationBasis:           req.ExpirationBasis,
		MaxMachines:               req.MaxMachines,
		MaxSeats:                  req.MaxSeats,
		ValidationTTLSec:          req.ValidationTTLSec,
		Floating:                  req.Floating,
		Strict:                    req.Strict,
		RequireCheckout:           req.RequireCheckout,
		CheckoutIntervalSec:       req.CheckoutIntervalSec,
		MaxCheckoutDurationSec:    req.MaxCheckoutDurationSec,
		CheckoutGraceSec:          req.CheckoutGraceSec,
		ComponentMatchingStrategy: req.ComponentMatchingStrategy,
		Metadata:                  req.Metadata,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}
	if err := s.repo.Create(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

func validateCreate(req *CreateRequest) error {
	if strings.TrimSpace(req.Name) == "" {
		return core.NewAppError(core.ErrValidationError, "name is required")
	}
	if req.ExpirationStrategy != "" && !req.ExpirationStrategy.IsValid() {
		return core.NewAppError(core.ErrPolicyInvalidStrategy, "unknown expiration_strategy")
	}
	if req.ExpirationBasis != "" && !req.ExpirationBasis.IsValid() {
		return core.NewAppError(core.ErrPolicyInvalidBasis, "unknown expiration_basis")
	}
	if req.ComponentMatchingStrategy != "" && !req.ComponentMatchingStrategy.IsValid() {
		return core.NewAppError(core.ErrPolicyInvalidStrategy, "unknown component_matching_strategy")
	}
	if req.DurationSeconds != nil && *req.DurationSeconds <= 0 {
		return core.NewAppError(core.ErrPolicyInvalidDuration, "duration_seconds must be positive")
	}
	if req.MaxMachines != nil && *req.MaxMachines < 1 {
		return core.NewAppError(core.ErrValidationError, "max_machines must be positive")
	}
	if req.MaxSeats != nil && *req.MaxSeats < 1 {
		return core.NewAppError(core.ErrValidationError, "max_seats must be positive")
	}
	if req.CheckoutIntervalSec < 0 || req.MaxCheckoutDurationSec < 0 || req.CheckoutGraceSec < 0 {
		return core.NewAppError(core.ErrPolicyInvalidDuration, "checkout intervals must be non-negative")
	}
	if req.ValidationTTLSec != nil {
		if *req.ValidationTTLSec < 60 || *req.ValidationTTLSec > 2_592_000 {
			return core.NewAppError(core.ErrPolicyInvalidTTL, "validation_ttl_sec must be between 60 and 2592000")
		}
	}
	return nil
}

func applyCreateDefaults(req *CreateRequest) {
	if req.ExpirationStrategy == "" {
		req.ExpirationStrategy = core.ExpirationStrategyRevokeAccess
	}
	if req.ExpirationBasis == "" {
		req.ExpirationBasis = core.ExpirationBasisFromCreation
	}
	if req.ComponentMatchingStrategy == "" {
		req.ComponentMatchingStrategy = core.ComponentMatchingAny
	}
	if req.CheckoutIntervalSec == 0 {
		req.CheckoutIntervalSec = 86400
	}
	if req.MaxCheckoutDurationSec == 0 {
		req.MaxCheckoutDurationSec = 604800
	}
	if req.CheckoutGraceSec == 0 {
		req.CheckoutGraceSec = 86400
	}
}

// CreateDefault is called by product.Service.Create inside the product
// creation tx. It makes a "Default" policy with sensible zero-config
// starting values and marks it is_default.
func (s *Service) CreateDefault(ctx context.Context, accountID core.AccountID, productID core.ProductID) (*domain.Policy, error) {
	return s.Create(ctx, accountID, productID, CreateRequest{Name: "Default"}, true)
}

func (s *Service) Get(ctx context.Context, id core.PolicyID) (*domain.Policy, error) {
	p, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, core.NewAppError(core.ErrPolicyNotFound, "policy not found")
	}
	return p, nil
}

func (s *Service) GetDefault(ctx context.Context, productID core.ProductID) (*domain.Policy, error) {
	p, err := s.repo.GetDefaultForProduct(ctx, productID)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, core.NewAppError(core.ErrPolicyNotFound, "policy not found")
	}
	return p, nil
}

func (s *Service) ListByProduct(ctx context.Context, productID core.ProductID, cursor core.Cursor, limit int) ([]domain.Policy, bool, error) {
	return s.repo.GetByProduct(ctx, productID, cursor, limit)
}

func (s *Service) Update(ctx context.Context, id core.PolicyID, req UpdateRequest) (*domain.Policy, error) {
	p, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if req.Name != nil {
		p.Name = *req.Name
	}
	if req.DurationSeconds != nil {
		p.DurationSeconds = *req.DurationSeconds
	}
	if req.ExpirationStrategy != nil {
		if !req.ExpirationStrategy.IsValid() {
			return nil, core.NewAppError(core.ErrPolicyInvalidStrategy, "unknown expiration_strategy")
		}
		p.ExpirationStrategy = *req.ExpirationStrategy
	}
	if req.ExpirationBasis != nil {
		if !req.ExpirationBasis.IsValid() {
			return nil, core.NewAppError(core.ErrPolicyInvalidBasis, "unknown expiration_basis")
		}
		p.ExpirationBasis = *req.ExpirationBasis
	}
	if req.MaxMachines != nil {
		p.MaxMachines = *req.MaxMachines
	}
	if req.MaxSeats != nil {
		p.MaxSeats = *req.MaxSeats
	}
	if req.ValidationTTLSec != nil {
		if *req.ValidationTTLSec != nil {
			v := **req.ValidationTTLSec
			if v < 60 || v > 2_592_000 {
				return nil, core.NewAppError(core.ErrPolicyInvalidTTL, "validation_ttl_sec must be between 60 and 2592000")
			}
		}
		p.ValidationTTLSec = *req.ValidationTTLSec
	}
	if req.Floating != nil {
		p.Floating = *req.Floating
	}
	if req.Strict != nil {
		p.Strict = *req.Strict
	}
	if req.RequireCheckout != nil {
		p.RequireCheckout = *req.RequireCheckout
	}
	if req.CheckoutIntervalSec != nil {
		p.CheckoutIntervalSec = *req.CheckoutIntervalSec
	}
	if req.MaxCheckoutDurationSec != nil {
		p.MaxCheckoutDurationSec = *req.MaxCheckoutDurationSec
	}
	if req.CheckoutGraceSec != nil {
		p.CheckoutGraceSec = *req.CheckoutGraceSec
	}
	if req.ComponentMatchingStrategy != nil {
		if !req.ComponentMatchingStrategy.IsValid() {
			return nil, core.NewAppError(core.ErrPolicyInvalidStrategy, "unknown component_matching_strategy")
		}
		p.ComponentMatchingStrategy = *req.ComponentMatchingStrategy
	}
	if req.Metadata != nil {
		p.Metadata = *req.Metadata
	}
	p.UpdatedAt = time.Now().UTC()
	if err := s.repo.Update(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Service) SetDefault(ctx context.Context, policyID core.PolicyID) error {
	p, err := s.Get(ctx, policyID)
	if err != nil {
		return err
	}
	return s.repo.SetDefault(ctx, p.ProductID, policyID)
}

// Delete refuses the default policy and (without force) refuses any
// policy that is referenced by licenses.
func (s *Service) Delete(ctx context.Context, policyID core.PolicyID, force bool) error {
	p, err := s.Get(ctx, policyID)
	if err != nil {
		return err
	}
	if p.IsDefault {
		return core.NewAppError(core.ErrPolicyIsDefault, "cannot delete the default policy")
	}
	n, err := s.repo.CountReferencingLicenses(ctx, policyID)
	if err != nil {
		return err
	}
	if n > 0 && !force {
		return core.NewAppError(core.ErrPolicyInUse, "policy referenced by licenses; use ?force=true")
	}
	if n > 0 && force {
		def, err := s.GetDefault(ctx, p.ProductID)
		if err != nil {
			return err
		}
		if _, err := s.repo.ReassignLicensesFromPolicy(ctx, policyID, def.ID); err != nil {
			return err
		}
	}
	return s.repo.Delete(ctx, policyID)
}
