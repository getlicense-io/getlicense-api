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

type Service struct {
	txManager domain.TxManager
	licenses  domain.LicenseRepository
	products  domain.ProductRepository
	machines  domain.MachineRepository
	masterKey *crypto.MasterKey
}

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

type CreateRequest struct {
	LicenseType   string           `json:"license_type" validate:"required,oneof=perpetual timed subscription trial"`
	MaxMachines   *int             `json:"max_machines"`
	MaxSeats      *int             `json:"max_seats"`
	Entitlements  *json.RawMessage `json:"entitlements"`
	LicenseeName  *string          `json:"licensee_name"`
	LicenseeEmail *string          `json:"licensee_email"`
	ExpiresAt     *time.Time       `json:"expires_at"`
}

type CreateResult struct {
	License    *domain.License `json:"license"`
	LicenseKey string          `json:"license_key"`
}

type ValidateResult struct {
	Valid   bool            `json:"valid"`
	License *domain.License `json:"license"`
}

type ActivateRequest struct {
	Fingerprint string           `json:"fingerprint" validate:"required"`
	Hostname    *string          `json:"hostname"`
	Metadata    *json.RawMessage `json:"metadata"`
}

type DeactivateRequest struct {
	Fingerprint string `json:"fingerprint" validate:"required"`
}

type HeartbeatRequest struct {
	Fingerprint string `json:"fingerprint" validate:"required"`
}

func (s *Service) Create(ctx context.Context, accountID core.AccountID, productID core.ProductID, req CreateRequest) (*CreateResult, error) {
	licenseType, err := core.ParseLicenseType(req.LicenseType)
	if err != nil {
		return nil, core.NewAppError(core.ErrValidationError, "Invalid license type")
	}

	// Pre-generate values outside the transaction to minimize connection hold time.
	fullKey, prefix, err := GenerateLicenseKey()
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to generate license key")
	}
	licenseID := core.NewLicenseID()
	now := time.Now().UTC()
	keyHash := s.masterKey.HMAC(fullKey)

	var entitlements json.RawMessage
	if req.Entitlements != nil {
		entitlements = *req.Entitlements
	}

	var result *CreateResult

	err = s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		product, err := s.products.GetByID(ctx, productID)
		if err != nil {
			return err
		}
		if product == nil {
			return core.NewAppError(core.ErrProductNotFound, "Product not found")
		}

		privKeyBytes, err := s.masterKey.Decrypt(product.PrivateKeyEnc)
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to decrypt product private key")
		}

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

		token, err := crypto.SignToken(payload, ed25519.PrivateKey(privKeyBytes))
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to sign license token")
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

		result = &CreateResult{License: license, LicenseKey: fullKey}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

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

func (s *Service) Get(ctx context.Context, accountID core.AccountID, licenseID core.LicenseID) (*domain.License, error) {
	var result *domain.License

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		l, err := s.requireLicense(ctx, licenseID)
		if err != nil {
			return err
		}
		result = l
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) Revoke(ctx context.Context, accountID core.AccountID, licenseID core.LicenseID) error {
	_, err := s.transitionStatus(ctx, accountID, licenseID,
		func(st core.LicenseStatus) bool { return st.CanRevoke() },
		core.LicenseStatusRevoked,
		"License cannot be revoked from current status",
	)
	return err
}

func (s *Service) Suspend(ctx context.Context, accountID core.AccountID, licenseID core.LicenseID) (*domain.License, error) {
	return s.transitionStatus(ctx, accountID, licenseID,
		func(st core.LicenseStatus) bool { return st.CanSuspend() },
		core.LicenseStatusSuspended,
		"License cannot be suspended from current status",
	)
}

func (s *Service) Reinstate(ctx context.Context, accountID core.AccountID, licenseID core.LicenseID) (*domain.License, error) {
	return s.transitionStatus(ctx, accountID, licenseID,
		func(st core.LicenseStatus) bool { return st.CanReinstate() },
		core.LicenseStatusActive,
		"License cannot be reinstated from current status",
	)
}

// Validate looks up a license by its raw key and checks status.
// No tenant context needed — this is a public endpoint.
func (s *Service) Validate(ctx context.Context, licenseKey string) (*ValidateResult, error) {
	keyHash := s.masterKey.HMAC(licenseKey)

	license, err := s.licenses.GetByKeyHash(ctx, keyHash)
	if err != nil {
		return nil, err
	}
	if license == nil {
		return nil, core.NewAppError(core.ErrInvalidLicenseKey, "Invalid license key")
	}

	if err := core.ValidateLicenseStatus(license.Status, license.ExpiresAt); err != nil {
		return nil, err
	}

	return &ValidateResult{Valid: true, License: license}, nil
}

func (s *Service) Activate(ctx context.Context, accountID core.AccountID, licenseID core.LicenseID, req ActivateRequest) (*domain.Machine, error) {
	if err := ValidateFingerprint(req.Fingerprint); err != nil {
		return nil, err
	}

	var result *domain.Machine

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		license, err := s.licenses.GetByIDForUpdate(ctx, licenseID)
		if err != nil {
			return err
		}
		if license == nil {
			return core.NewAppError(core.ErrLicenseNotFound, "License not found")
		}

		// Ensure license is in a valid state for activation.
		if err := core.ValidateLicenseStatus(license.Status, license.ExpiresAt); err != nil {
			return err
		}

		existing, err := s.machines.GetByFingerprint(ctx, licenseID, req.Fingerprint)
		if err != nil {
			return err
		}
		if existing != nil {
			return core.NewAppError(core.ErrMachineAlreadyActivated, "Machine is already activated for this license")
		}

		if license.MaxMachines != nil {
			count, err := s.machines.CountByLicense(ctx, licenseID)
			if err != nil {
				return err
			}
			if count >= *license.MaxMachines {
				return core.NewAppError(core.ErrMachineLimitExceeded, "Machine limit exceeded")
			}
		}

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

func (s *Service) Deactivate(ctx context.Context, accountID core.AccountID, licenseID core.LicenseID, req DeactivateRequest) error {
	if err := ValidateFingerprint(req.Fingerprint); err != nil {
		return err
	}

	return s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		return s.machines.DeleteByFingerprint(ctx, licenseID, req.Fingerprint)
	})
}

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

// --- Private helpers ---

// requireLicense fetches a license by ID and returns ErrLicenseNotFound if missing.
func (s *Service) requireLicense(ctx context.Context, id core.LicenseID) (*domain.License, error) {
	license, err := s.licenses.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if license == nil {
		return nil, core.NewAppError(core.ErrLicenseNotFound, "License not found")
	}
	return license, nil
}

// transitionStatus is the shared implementation for Revoke, Suspend, and Reinstate.
func (s *Service) transitionStatus(
	ctx context.Context,
	accountID core.AccountID,
	licenseID core.LicenseID,
	canTransition func(core.LicenseStatus) bool,
	target core.LicenseStatus,
	errMsg string,
) (*domain.License, error) {
	var result *domain.License

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		license, err := s.requireLicense(ctx, licenseID)
		if err != nil {
			return err
		}
		if !canTransition(license.Status) {
			return core.NewAppError(core.ErrValidationError, errMsg)
		}
		updatedAt, err := s.licenses.UpdateStatus(ctx, licenseID, license.Status, target)
		if err != nil {
			return err
		}
		license.Status = target
		license.UpdatedAt = updatedAt
		result = license
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
