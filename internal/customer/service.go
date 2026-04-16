// Package customer owns the customer registry — end-user records
// referenced by licenses. Customers are account-scoped and have no
// login in v1. The portal is explicit v2 (see FEATURES.md §6).
//
// Service methods are pure business logic — they do NOT open their
// own transactions. Callers (HTTP handlers OR other services like
// licensing.Service.Create) are responsible for tx discipline. This
// mirrors the policy.Service pattern so callers can compose
// customer operations into wider transactions without nested-tx issues.
package customer

import (
	"context"
	"encoding/json"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

type Service struct {
	repo domain.CustomerRepository
}

func NewService(repo domain.CustomerRepository) *Service {
	return &Service{repo: repo}
}

// CreateRequest is the public create shape.
type CreateRequest struct {
	Email    string          `json:"email"`
	Name     *string         `json:"name,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// UpdateRequest is the partial update shape. Omitted fields unchanged.
type UpdateRequest struct {
	Name     *string          `json:"name,omitempty"`
	Metadata *json.RawMessage `json:"metadata,omitempty"`
}

// UpsertRequest is used internally by licensing.Service.Create when
// the caller passes inline customer details.
type UpsertRequest struct {
	Email              string
	Name               *string
	Metadata           json.RawMessage
	CreatedByAccountID *core.AccountID
}

// Create inserts a new customer. Email is normalized and validated
// before the insert. Duplicate email within the account is surfaced
// as the DB unique-violation error; the caller (typically a handler)
// should return 409 in that case.
func (s *Service) Create(ctx context.Context, accountID core.AccountID, req CreateRequest) (*domain.Customer, error) {
	email, err := NormalizeEmail(req.Email)
	if err != nil {
		return nil, err
	}
	c := &domain.Customer{
		ID:        core.NewCustomerID(),
		AccountID: accountID,
		Email:     email,
		Name:      req.Name,
		Metadata:  req.Metadata,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := s.repo.Create(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

// Get fetches a customer by ID; translates repo nil to ErrCustomerNotFound.
func (s *Service) Get(ctx context.Context, id core.CustomerID) (*domain.Customer, error) {
	c, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, core.NewAppError(core.ErrCustomerNotFound, "customer not found")
	}
	return c, nil
}

// List returns a paginated customer list for the account.
func (s *Service) List(ctx context.Context, accountID core.AccountID, filter domain.CustomerListFilter, cursor core.Cursor, limit int) ([]domain.Customer, bool, error) {
	return s.repo.List(ctx, accountID, filter, cursor, limit)
}

// Update mutates name and/or metadata. Email is immutable post-create.
func (s *Service) Update(ctx context.Context, id core.CustomerID, req UpdateRequest) (*domain.Customer, error) {
	c, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if req.Name != nil {
		c.Name = req.Name
	}
	if req.Metadata != nil {
		c.Metadata = *req.Metadata
	}
	c.UpdatedAt = time.Now().UTC()
	if err := s.repo.Update(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

// Delete refuses to remove a customer that has licenses.
func (s *Service) Delete(ctx context.Context, id core.CustomerID) error {
	if _, err := s.Get(ctx, id); err != nil {
		return err
	}
	n, err := s.repo.CountReferencingLicenses(ctx, id)
	if err != nil {
		return err
	}
	if n > 0 {
		return core.NewAppError(core.ErrCustomerInUse, "customer is referenced by licenses")
	}
	return s.repo.Delete(ctx, id)
}

// UpsertForLicense is called by licensing.Service.Create with inline
// customer details. Returns the existing or newly inserted customer.
// Attribution: CreatedByAccountID is set to the grantee account on
// inserts only; first-write-wins on conflicts.
func (s *Service) UpsertForLicense(ctx context.Context, accountID core.AccountID, req UpsertRequest) (*domain.Customer, error) {
	email, err := NormalizeEmail(req.Email)
	if err != nil {
		return nil, err
	}
	c, _, err := s.repo.UpsertByEmail(ctx, accountID, email, req.Name, req.Metadata, req.CreatedByAccountID)
	return c, err
}
