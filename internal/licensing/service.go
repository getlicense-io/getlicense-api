package licensing

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Service handles license lifecycle and machine operations.
type Service struct {
	txManager domain.TxManager
	licenses  domain.LicenseRepository
	products  domain.ProductRepository
	machines  domain.MachineRepository
	masterKey *crypto.MasterKey
}

// NewService constructs a new licensing Service.
func NewService(
	txManager domain.TxManager,
	licenses domain.LicenseRepository,
	products domain.ProductRepository,
	machines domain.MachineRepository,
	masterKey *crypto.MasterKey,
) *Service {
	return &Service{
		txManager: txManager,
		licenses:  licenses,
		products:  products,
		machines:  machines,
		masterKey: masterKey,
	}
}

// --- Request / Result types ---

// CreateRequest holds the parameters for creating a new license.
type CreateRequest struct {
	LicenseType   string           `json:"license_type" validate:"required,oneof=perpetual timed subscription trial"`
	MaxMachines   *int             `json:"max_machines"`
	MaxSeats      *int             `json:"max_seats"`
	Entitlements  *json.RawMessage `json:"entitlements"`
	LicenseeName  *string          `json:"licensee_name"`
	LicenseeEmail *string          `json:"licensee_email"`
	ExpiresAt     *time.Time       `json:"expires_at"`
}

// CreateResult is the output of a successful license creation.
type CreateResult struct {
	License    *domain.License `json:"license"`
	LicenseKey string          `json:"license_key"`
}

// ValidateResult is the output of a license validation.
type ValidateResult struct {
	Valid   bool            `json:"valid"`
	License *domain.License `json:"license"`
}

// ActivateRequest holds the parameters for activating a machine.
type ActivateRequest struct {
	Fingerprint string           `json:"fingerprint" validate:"required"`
	Hostname    *string          `json:"hostname"`
	Metadata    *json.RawMessage `json:"metadata"`
}

// DeactivateRequest holds the parameters for deactivating a machine.
type DeactivateRequest struct {
	Fingerprint string `json:"fingerprint" validate:"required"`
}

// HeartbeatRequest holds the parameters for a machine heartbeat.
type HeartbeatRequest struct {
	Fingerprint string `json:"fingerprint" validate:"required"`
}

// --- Methods ---

// Create generates a license key, signs a token, and persists the license.
func (s *Service) Create(ctx context.Context, accountID core.AccountID, productID core.ProductID, req CreateRequest) (*CreateResult, error) {
	// Parse and validate the license type.
	licenseType, err := core.ParseLicenseType(req.LicenseType)
	if err != nil {
		return nil, core.NewAppError(core.ErrValidationError, "Invalid license type")
	}

	var result *CreateResult

	err = s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		// Look up the product.
		product, err := s.products.GetByID(ctx, productID)
		if err != nil {
			return err
		}
		if product == nil {
			return core.NewAppError(core.ErrProductNotFound, "Product not found")
		}

		// Decrypt the product's private key.
		privKeyBytes, err := crypto.DecryptAESGCM(s.masterKey.EncryptionKey, product.PrivateKeyEnc)
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to decrypt product private key")
		}
		privKey := ed25519.PrivateKey(privKeyBytes)

		// Generate a license key.
		fullKey, prefix, err := GenerateLicenseKey()
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to generate license key")
		}

		licenseID := core.NewLicenseID()
		now := time.Now().UTC()

		// Build the token payload.
		payload := crypto.TokenPayload{
			Version:     1,
			ProductID:   productID.String(),
			LicenseID:   licenseID.String(),
			Type:        licenseType,
			Status:      core.LicenseStatusActive,
			MaxMachines: req.MaxMachines,
			IssuedAt:    now.Unix(),
			TTL:         product.ValidationTTL,
		}
		if req.Entitlements != nil {
			payload.Entitlements = *req.Entitlements
		}
		if req.ExpiresAt != nil {
			exp := req.ExpiresAt.Unix()
			payload.ExpiresAt = &exp
		}

		// Sign the token.
		token, err := crypto.SignToken(payload, privKey)
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to sign license token")
		}

		// HMAC-hash the license key for storage.
		keyHash := crypto.HMACSHA256(s.masterKey.HMACKey, fullKey)

		// Resolve optional fields.
		var entitlements json.RawMessage
		if req.Entitlements != nil {
			entitlements = *req.Entitlements
		}

		license := &domain.License{
			ID:            licenseID,
			AccountID:     accountID,
			ProductID:     productID,
			KeyPrefix:     prefix,
			KeyHash:       keyHash,
			Token:         token,
			LicenseType:   licenseType,
			Status:        core.LicenseStatusActive,
			MaxMachines:   req.MaxMachines,
			MaxSeats:      req.MaxSeats,
			Entitlements:  entitlements,
			LicenseeName:  req.LicenseeName,
			LicenseeEmail: req.LicenseeEmail,
			ExpiresAt:     req.ExpiresAt,
			CreatedAt:     now,
			UpdatedAt:     now,
		}

		if err := s.licenses.Create(ctx, license); err != nil {
			return err
		}

		result = &CreateResult{
			License:    license,
			LicenseKey: fullKey,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// List returns a paginated slice of licenses for the given account.
func (s *Service) List(ctx context.Context, accountID core.AccountID, limit, offset int) ([]domain.License, int, error) {
	var licenses []domain.License
	var total int

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		var err error
		licenses, total, err = s.licenses.List(ctx, limit, offset)
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return licenses, total, nil
}

// Get retrieves a single license by ID within the given account.
func (s *Service) Get(ctx context.Context, accountID core.AccountID, licenseID core.LicenseID) (*domain.License, error) {
	var result *domain.License

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		l, err := s.licenses.GetByID(ctx, licenseID)
		if err != nil {
			return err
		}
		if l == nil {
			return core.NewAppError(core.ErrLicenseNotFound, "License not found")
		}
		result = l
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Revoke permanently revokes a license.
func (s *Service) Revoke(ctx context.Context, accountID core.AccountID, licenseID core.LicenseID) error {
	return s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		license, err := s.licenses.GetByID(ctx, licenseID)
		if err != nil {
			return err
		}
		if license == nil {
			return core.NewAppError(core.ErrLicenseNotFound, "License not found")
		}
		if !license.Status.CanRevoke() {
			return core.NewAppError(core.ErrValidationError, "License cannot be revoked from current status")
		}
		return s.licenses.UpdateStatus(ctx, licenseID, core.LicenseStatusRevoked)
	})
}

// Suspend temporarily suspends a license.
func (s *Service) Suspend(ctx context.Context, accountID core.AccountID, licenseID core.LicenseID) (*domain.License, error) {
	var result *domain.License

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		license, err := s.licenses.GetByID(ctx, licenseID)
		if err != nil {
			return err
		}
		if license == nil {
			return core.NewAppError(core.ErrLicenseNotFound, "License not found")
		}
		if !license.Status.CanSuspend() {
			return core.NewAppError(core.ErrValidationError, "License cannot be suspended from current status")
		}
		if err := s.licenses.UpdateStatus(ctx, licenseID, core.LicenseStatusSuspended); err != nil {
			return err
		}
		license.Status = core.LicenseStatusSuspended
		license.UpdatedAt = time.Now().UTC()
		result = license
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Reinstate reactivates a suspended license.
func (s *Service) Reinstate(ctx context.Context, accountID core.AccountID, licenseID core.LicenseID) (*domain.License, error) {
	var result *domain.License

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		license, err := s.licenses.GetByID(ctx, licenseID)
		if err != nil {
			return err
		}
		if license == nil {
			return core.NewAppError(core.ErrLicenseNotFound, "License not found")
		}
		if !license.Status.CanReinstate() {
			return core.NewAppError(core.ErrValidationError, "License cannot be reinstated from current status")
		}
		if err := s.licenses.UpdateStatus(ctx, licenseID, core.LicenseStatusActive); err != nil {
			return err
		}
		license.Status = core.LicenseStatusActive
		license.UpdatedAt = time.Now().UTC()
		result = license
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Validate looks up a license by its raw key (HMAC-hashed) and checks status.
// This is a global operation -- no tenant context or transaction is required.
func (s *Service) Validate(ctx context.Context, licenseKey string) (*ValidateResult, error) {
	keyHash := crypto.HMACSHA256(s.masterKey.HMACKey, licenseKey)

	license, err := s.licenses.GetByKeyHash(ctx, keyHash)
	if err != nil {
		return nil, err
	}
	if license == nil {
		return nil, core.NewAppError(core.ErrInvalidLicenseKey, "Invalid license key")
	}

	if err := ValidateLicenseStatus(license.Status, license.ExpiresAt); err != nil {
		return nil, err
	}

	return &ValidateResult{Valid: true, License: license}, nil
}

// Activate registers a new machine for a license.
func (s *Service) Activate(ctx context.Context, accountID core.AccountID, licenseID core.LicenseID, req ActivateRequest) (*domain.Machine, error) {
	if err := ValidateFingerprint(req.Fingerprint); err != nil {
		return nil, err
	}

	var result *domain.Machine

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		// Verify the license exists.
		license, err := s.licenses.GetByID(ctx, licenseID)
		if err != nil {
			return err
		}
		if license == nil {
			return core.NewAppError(core.ErrLicenseNotFound, "License not found")
		}

		// Check for duplicate fingerprint.
		existing, err := s.machines.GetByFingerprint(ctx, licenseID, req.Fingerprint)
		if err != nil {
			return err
		}
		if existing != nil {
			return core.NewAppError(core.ErrMachineAlreadyActivated, "Machine is already activated for this license")
		}

		// Enforce machine limit if set.
		if license.MaxMachines != nil {
			count, err := s.machines.CountByLicense(ctx, licenseID)
			if err != nil {
				return err
			}
			if count >= *license.MaxMachines {
				return core.NewAppError(core.ErrMachineLimitExceeded, "Machine limit exceeded")
			}
		}

		// Resolve optional metadata.
		var metadata json.RawMessage
		if req.Metadata != nil {
			metadata = *req.Metadata
		}

		now := time.Now().UTC()
		machine := &domain.Machine{
			ID:          core.NewMachineID(),
			AccountID:   accountID,
			LicenseID:   licenseID,
			Fingerprint: req.Fingerprint,
			Hostname:    req.Hostname,
			Metadata:    metadata,
			CreatedAt:   now,
		}

		if err := s.machines.Create(ctx, machine); err != nil {
			return err
		}

		result = machine
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Deactivate removes a machine by fingerprint.
func (s *Service) Deactivate(ctx context.Context, accountID core.AccountID, licenseID core.LicenseID, req DeactivateRequest) error {
	if err := ValidateFingerprint(req.Fingerprint); err != nil {
		return err
	}

	return s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		return s.machines.DeleteByFingerprint(ctx, licenseID, req.Fingerprint)
	})
}

// Heartbeat updates the last-seen timestamp for a machine.
func (s *Service) Heartbeat(ctx context.Context, accountID core.AccountID, licenseID core.LicenseID, req HeartbeatRequest) (*domain.Machine, error) {
	if err := ValidateFingerprint(req.Fingerprint); err != nil {
		return nil, err
	}

	var result *domain.Machine

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		m, err := s.machines.UpdateHeartbeat(ctx, licenseID, req.Fingerprint)
		if err != nil {
			return err
		}
		result = m
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
