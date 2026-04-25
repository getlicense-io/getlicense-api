package product

import (
	"context"
	"encoding/json"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/policy"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// Service handles product lifecycle operations.
type Service struct {
	txManager domain.TxManager
	products  domain.ProductRepository
	licenses  domain.LicenseRepository
	policy    *policy.Service
	masterKey *crypto.MasterKey
}

// NewService constructs a new product Service.
func NewService(txManager domain.TxManager, products domain.ProductRepository, licenses domain.LicenseRepository, policySvc *policy.Service, masterKey *crypto.MasterKey) *Service {
	return &Service{
		txManager: txManager,
		products:  products,
		licenses:  licenses,
		policy:    policySvc,
		masterKey: masterKey,
	}
}

type CreateRequest struct {
	Name     string           `json:"name" validate:"required,min=1,max=100"`
	Slug     string           `json:"slug" validate:"required,min=1,max=100"`
	Metadata *json.RawMessage `json:"metadata"`
}

type UpdateRequest struct {
	Name     *string          `json:"name"`
	Metadata *json.RawMessage `json:"metadata"`
}

// Create generates a new Ed25519 keypair, encrypts the private key, persists the
// product, and auto-creates a Default policy inside the same transaction so
// every product ships with a usable policy from the start.
func (s *Service) Create(ctx context.Context, accountID core.AccountID, env core.Environment, req CreateRequest) (*domain.Product, error) {
	var result *domain.Product

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		pub, priv, err := crypto.GenerateEd25519Keypair()
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to generate Ed25519 keypair")
		}

		privKeyEnc, err := s.masterKey.Encrypt(priv)
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to encrypt private key")
		}

		pubKeyEncoded := crypto.EncodePublicKey(pub)

		var metadata json.RawMessage
		if req.Metadata != nil {
			metadata = *req.Metadata
		}

		product := &domain.Product{
			ID:            core.NewProductID(),
			AccountID:     accountID,
			Name:          req.Name,
			Slug:          req.Slug,
			PublicKey:     pubKeyEncoded,
			PrivateKeyEnc: privKeyEnc,
			Metadata:      metadata,
			CreatedAt:     time.Now().UTC(),
		}
		if err := s.products.Create(ctx, product); err != nil {
			return err
		}

		// Auto-create the Default policy in the same tx. A failure here
		// rolls back the product insert so we never leave a product
		// without a default policy.
		if _, err := s.policy.CreateDefault(ctx, accountID, product.ID); err != nil {
			return err
		}

		result = product
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) List(ctx context.Context, accountID core.AccountID, env core.Environment, cursor core.Cursor, limit int) ([]domain.Product, bool, error) {
	var products []domain.Product
	var hasMore bool

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		var err error
		products, hasMore, err = s.products.List(ctx, cursor, limit)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return products, hasMore, nil
}

// Get retrieves a single product by ID within the given account.
func (s *Service) Get(ctx context.Context, accountID core.AccountID, env core.Environment, productID core.ProductID) (*domain.Product, error) {
	if err := middleware.EnforceProductScope(ctx, productID); err != nil {
		return nil, err
	}
	var result *domain.Product

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		p, err := s.products.GetByID(ctx, productID)
		if err != nil {
			return err
		}
		if p == nil {
			return core.NewAppError(core.ErrProductNotFound, "Product not found")
		}
		result = p
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Update applies partial updates to an existing product.
func (s *Service) Update(ctx context.Context, accountID core.AccountID, env core.Environment, productID core.ProductID, req UpdateRequest) (*domain.Product, error) {
	if err := middleware.EnforceProductScope(ctx, productID); err != nil {
		return nil, err
	}
	var result *domain.Product

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		params := domain.UpdateProductParams{
			Name:     req.Name,
			Metadata: req.Metadata,
		}
		p, err := s.products.Update(ctx, productID, params)
		if err != nil {
			return err
		}
		result = p
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Delete removes a product by ID within the given account.
// Returns an error if the product has active or suspended licenses.
func (s *Service) Delete(ctx context.Context, accountID core.AccountID, env core.Environment, productID core.ProductID) error {
	if err := middleware.EnforceProductScope(ctx, productID); err != nil {
		return err
	}
	return s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		count, err := s.licenses.CountByProduct(ctx, productID)
		if err != nil {
			return err
		}
		if count > 0 {
			return core.NewAppError(core.ErrValidationError, "Cannot delete product with active or suspended licenses. Revoke them first.")
		}
		return s.products.Delete(ctx, productID)
	})
}
