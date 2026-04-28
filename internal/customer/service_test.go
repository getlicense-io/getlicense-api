package customer_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/customer"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

type fakeRepo struct {
	mu       sync.Mutex
	byID     map[core.CustomerID]*domain.Customer
	byEmail  map[string]core.CustomerID // key: accountID|lower(email)
	refCount map[core.CustomerID]int
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		byID:     map[core.CustomerID]*domain.Customer{},
		byEmail:  map[string]core.CustomerID{},
		refCount: map[core.CustomerID]int{},
	}
}

func emailKey(a core.AccountID, e string) string { return a.String() + "|" + e }

func (r *fakeRepo) Create(_ context.Context, c *domain.Customer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := emailKey(c.AccountID, c.Email)
	if _, exists := r.byEmail[k]; exists {
		return errors.New("unique violation")
	}
	r.byID[c.ID] = c
	r.byEmail[k] = c.ID
	return nil
}

func (r *fakeRepo) Get(_ context.Context, id core.CustomerID) (*domain.Customer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	return c, nil
}

func (r *fakeRepo) GetByEmail(_ context.Context, accountID core.AccountID, email string) (*domain.Customer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.byEmail[emailKey(accountID, email)]
	if !ok {
		return nil, nil
	}
	return r.byID[id], nil
}

func (r *fakeRepo) List(context.Context, core.AccountID, domain.CustomerListFilter, core.Cursor, int) ([]domain.Customer, bool, error) {
	return nil, false, nil
}

func (r *fakeRepo) Update(_ context.Context, c *domain.Customer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[c.ID]; !ok {
		return core.NewAppError(core.ErrCustomerNotFound, "not found")
	}
	r.byID[c.ID] = c
	return nil
}

func (r *fakeRepo) Delete(_ context.Context, id core.CustomerID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byID[id]
	if !ok {
		return core.NewAppError(core.ErrCustomerNotFound, "not found")
	}
	delete(r.byID, id)
	delete(r.byEmail, emailKey(c.AccountID, c.Email))
	return nil
}

func (r *fakeRepo) CountReferencingLicenses(_ context.Context, id core.CustomerID) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.refCount[id], nil
}

func (r *fakeRepo) Count(_ context.Context) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byID), nil
}

func (r *fakeRepo) UpsertByEmail(_ context.Context, accountID core.AccountID, email string, name *string, metadata json.RawMessage, createdByAccountID *core.AccountID) (*domain.Customer, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok := r.byEmail[emailKey(accountID, email)]; ok {
		return r.byID[id], false, nil
	}
	c := &domain.Customer{
		ID:                 core.NewCustomerID(),
		AccountID:          accountID,
		Email:              email,
		Name:               name,
		Metadata:           metadata,
		CreatedByAccountID: createdByAccountID,
	}
	r.byID[c.ID] = c
	r.byEmail[emailKey(accountID, email)] = c.ID
	return c, true, nil
}

func TestService_Create(t *testing.T) {
	repo := newFakeRepo()
	svc := customer.NewService(repo)
	c, err := svc.Create(context.Background(), core.NewAccountID(), customer.CreateRequest{
		Email: "Alice@Example.COM",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Email != "alice@example.com" {
		t.Errorf("email not normalized: got %q", c.Email)
	}
}

func TestService_Create_InvalidEmail(t *testing.T) {
	svc := customer.NewService(newFakeRepo())
	_, err := svc.Create(context.Background(), core.NewAccountID(), customer.CreateRequest{Email: "not-an-email"})
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCustomerInvalidEmail {
		t.Errorf("want customer_invalid_email, got %v", err)
	}
}

func TestService_GetNotFound(t *testing.T) {
	svc := customer.NewService(newFakeRepo())
	_, err := svc.Get(context.Background(), core.NewCustomerID())
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCustomerNotFound {
		t.Errorf("want customer_not_found, got %v", err)
	}
}

func TestService_DeleteInUse(t *testing.T) {
	repo := newFakeRepo()
	svc := customer.NewService(repo)
	c, _ := svc.Create(context.Background(), core.NewAccountID(), customer.CreateRequest{Email: "user@example.com"})
	repo.refCount[c.ID] = 3
	err := svc.Delete(context.Background(), c.ID)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCustomerInUse {
		t.Errorf("want customer_in_use, got %v", err)
	}
}

func TestService_DeleteSuccess(t *testing.T) {
	repo := newFakeRepo()
	svc := customer.NewService(repo)
	c, _ := svc.Create(context.Background(), core.NewAccountID(), customer.CreateRequest{Email: "user@example.com"})
	if err := svc.Delete(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(context.Background(), c.ID); err == nil {
		t.Error("customer should be deleted")
	}
}

func TestService_UpsertForLicense_NewThenReuse(t *testing.T) {
	repo := newFakeRepo()
	svc := customer.NewService(repo)
	acc := core.NewAccountID()
	c1, err := svc.UpsertForLicense(context.Background(), acc, customer.UpsertRequest{Email: "bob@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := svc.UpsertForLicense(context.Background(), acc, customer.UpsertRequest{Email: "BOB@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if c1.ID != c2.ID {
		t.Errorf("case-insensitive upsert should return same row: %v vs %v", c1.ID, c2.ID)
	}
}

func TestService_UpsertForLicense_DoesNotMutateExistingName(t *testing.T) {
	repo := newFakeRepo()
	svc := customer.NewService(repo)
	acc := core.NewAccountID()
	firstName := "Original"
	_, err := svc.UpsertForLicense(context.Background(), acc, customer.UpsertRequest{Email: "a@b.com", Name: &firstName})
	if err != nil {
		t.Fatal(err)
	}
	secondName := "Updated"
	c2, err := svc.UpsertForLicense(context.Background(), acc, customer.UpsertRequest{Email: "a@b.com", Name: &secondName})
	if err != nil {
		t.Fatal(err)
	}
	if c2.Name == nil || *c2.Name != "Original" {
		t.Errorf("existing customer name should not be overwritten: got %v", c2.Name)
	}
}

func TestService_UpsertForLicense_AttributionOnInsert(t *testing.T) {
	repo := newFakeRepo()
	svc := customer.NewService(repo)
	grantor := core.NewAccountID()
	grantee := core.NewAccountID()
	c, err := svc.UpsertForLicense(context.Background(), grantor, customer.UpsertRequest{
		Email:              "end@user.com",
		CreatedByAccountID: &grantee,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.CreatedByAccountID == nil || *c.CreatedByAccountID != grantee {
		t.Errorf("attribution not set: got %v, want %v", c.CreatedByAccountID, grantee)
	}
}
