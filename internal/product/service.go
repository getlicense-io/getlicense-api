package product

import (
	"context"
	"encoding/json"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

const (
	defaultValidationTTL = 86400  // 24 hours
	defaultGracePeriod   = 604800 // 7 days
)

// Service handles product lifecycle operations.
type Service struct {
	txManager domain.TxManager
	products  domain.ProductRepository
	masterKey *crypto.MasterKey
}

// NewService constructs a new product Service.
func NewService(txManager domain.TxManager, products domain.ProductRepository, masterKey *crypto.MasterKey) *Service {
	return &Service{
		txManager: txManager,
		products:  products,
		masterKey: masterKey,
	}
}

// --- Request types ---

type CreateRequest struct {
	Name          string           `json:"name" validate:"required,min=1,max=100"`
	Slug          string           `json:"slug" validate:"required,min=1,max=100"`
	ValidationTTL *int             `json:"validation_ttl"`
	GracePeriod   *int             `json:"grace_period"`
	Metadata      *json.RawMessage `json:"metadata"`
}

type UpdateRequest struct {
	Name          *string          `json:"name"`
	ValidationTTL *int             `json:"validation_ttl"`
	GracePeriod   *int             `json:"grace_period"`
	Metadata      *json.RawMessage `json:"metadata"`
}

// --- Methods ---

// Create generates a new Ed25519 keypair, encrypts the private key, and
// persists the product within a tenant-scoped transaction.
func (s *Service) Create(ctx context.Context, accountID core.AccountID, req CreateRequest) (*domain.Product, error) {
	var result *domain.Product

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		// Generate Ed25519 keypair.
		pub, priv, err := crypto.GenerateEd25519Keypair()
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to generate Ed25519 keypair")
		}

		// Encrypt private key with AES-GCM.
		privKeyEnc, err := s.masterKey.Encrypt(priv)
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to encrypt private key")
		}

		// Encode public key as base64url (no padding).
		pubKeyEncoded := crypto.EncodePublicKey(pub)

		// Apply defaults for optional fields.
		validationTTL := defaultValidationTTL
		if req.ValidationTTL != nil {
			validationTTL = *req.ValidationTTL
		}
		gracePeriod := defaultGracePeriod
		if req.GracePeriod != nil {
			gracePeriod = *req.GracePeriod
		}

		// Resolve metadata.
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
			ValidationTTL: validationTTL,
			GracePeriod:   gracePeriod,
			Metadata:      metadata,
			CreatedAt:     time.Now().UTC(),
		}
		if err := s.products.Create(ctx, product); err != nil {
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

// List returns a paginated slice of products for the given account.
func (s *Service) List(ctx context.Context, accountID core.AccountID, limit, offset int) ([]domain.Product, int, error) {
	var products []domain.Product
	var total int

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		var err error
		products, total, err = s.products.List(ctx, limit, offset)
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return products, total, nil
}

// Get retrieves a single product by ID within the given account.
func (s *Service) Get(ctx context.Context, accountID core.AccountID, productID core.ProductID) (*domain.Product, error) {
	var result *domain.Product

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
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
func (s *Service) Update(ctx context.Context, accountID core.AccountID, productID core.ProductID, req UpdateRequest) (*domain.Product, error) {
	var result *domain.Product

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		params := domain.UpdateProductParams{
			Name:          req.Name,
			ValidationTTL: req.ValidationTTL,
			GracePeriod:   req.GracePeriod,
			Metadata:      req.Metadata,
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
func (s *Service) Delete(ctx context.Context, accountID core.AccountID, productID core.ProductID) error {
	return s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		return s.products.Delete(ctx, productID)
	})
}
