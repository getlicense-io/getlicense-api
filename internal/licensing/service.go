package licensing

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"log/slog"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

type Service struct {
	txManager  domain.TxManager
	licenses   domain.LicenseRepository
	products   domain.ProductRepository
	machines   domain.MachineRepository
	masterKey  *crypto.MasterKey
	webhookSvc domain.EventDispatcher
}

func NewService(
	txManager domain.TxManager,
	licenses domain.LicenseRepository,
	products domain.ProductRepository,
	machines domain.MachineRepository,
	masterKey *crypto.MasterKey,
	webhookSvc domain.EventDispatcher,
) *Service {
	return &Service{
		txManager:  txManager,
		licenses:   licenses,
		products:   products,
		machines:   machines,
		masterKey:  masterKey,
		webhookSvc: webhookSvc,
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

type BulkCreateRequest struct {
	Licenses []CreateRequest `json:"licenses" validate:"required,min=1,max=100,dive"`
}

type BulkCreateResult struct {
	Results []CreateResult `json:"results"`
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

func (s *Service) Create(ctx context.Context, accountID core.AccountID, env core.Environment, productID core.ProductID, req CreateRequest) (*CreateResult, error) {
	// Pre-generate values outside the transaction to minimize connection hold time.
	fullKey, prefix, err := GenerateLicenseKey()
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to generate license key")
	}
	licenseID := core.NewLicenseID()
	now := time.Now().UTC()
	keyHash := s.masterKey.HMAC(fullKey)

	var result *CreateResult

	err = s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
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

		license, err := buildLicense(req, licenseID, prefix, keyHash, now, accountID, productID, product.ValidationTTL, ed25519.PrivateKey(privKeyBytes), env)
		if err != nil {
			return err
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
	s.dispatchEvent(ctx, accountID, env, core.EventTypeLicenseCreated, result.License)
	return result, nil
}

func (s *Service) BulkCreate(ctx context.Context, accountID core.AccountID, env core.Environment, productID core.ProductID, req BulkCreateRequest) (*BulkCreateResult, error) {
	// Pre-generate all keys, IDs, and HMACs outside the transaction.
	type pregenerated struct {
		fullKey   string
		prefix    string
		keyHash   string
		licenseID core.LicenseID
	}

	now := time.Now().UTC()
	pregens := make([]pregenerated, len(req.Licenses))
	for i := range req.Licenses {
		fullKey, prefix, err := GenerateLicenseKey()
		if err != nil {
			return nil, core.NewAppError(core.ErrInternalError, "Failed to generate license key")
		}
		pregens[i] = pregenerated{
			fullKey:   fullKey,
			prefix:    prefix,
			keyHash:   s.masterKey.HMAC(fullKey),
			licenseID: core.NewLicenseID(),
		}
	}

	var results []CreateResult

	err := s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
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
		privKey := ed25519.PrivateKey(privKeyBytes)

		allLicenses := make([]*domain.License, len(req.Licenses))
		results = make([]CreateResult, len(req.Licenses))

		for i, lr := range req.Licenses {
			pg := pregens[i]
			license, err := buildLicense(lr, pg.licenseID, pg.prefix, pg.keyHash, now, accountID, productID, product.ValidationTTL, privKey, env)
			if err != nil {
				return err
			}
			allLicenses[i] = license
			results[i] = CreateResult{License: license, LicenseKey: pg.fullKey}
		}

		return s.licenses.BulkCreate(ctx, allLicenses)
	})
	if err != nil {
		return nil, err
	}
	for _, r := range results {
		s.dispatchEvent(ctx, accountID, env, core.EventTypeLicenseCreated, r.License)
	}
	return &BulkCreateResult{Results: results}, nil
}

// List returns a paginated license listing for the tenant, optionally
// narrowed by status/type/q filters. Dashboards drive these from URL
// query params so filters survive pagination.
func (s *Service) List(ctx context.Context, accountID core.AccountID, env core.Environment, filters domain.LicenseListFilters, limit, offset int) ([]domain.License, int, error) {
	var licenses []domain.License
	var total int

	err := s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
		var err error
		licenses, total, err = s.licenses.List(ctx, filters, limit, offset)
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return licenses, total, nil
}

// ListByProduct returns a paginated slice of licenses for the given
// product within the env, optionally narrowed by filters. Validates
// that the product exists in this tenant before returning so callers
// get a clean 404 instead of an empty list when they're holding a
// stale ID.
func (s *Service) ListByProduct(ctx context.Context, accountID core.AccountID, env core.Environment, productID core.ProductID, filters domain.LicenseListFilters, limit, offset int) ([]domain.License, int, error) {
	var licenses []domain.License
	var total int

	err := s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
		product, err := s.products.GetByID(ctx, productID)
		if err != nil {
			return err
		}
		if product == nil {
			return core.NewAppError(core.ErrProductNotFound, "Product not found")
		}
		licenses, total, err = s.licenses.ListByProduct(ctx, productID, filters, limit, offset)
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return licenses, total, nil
}

// CountsByProductStatus returns a per-status license breakdown for
// the given product within the current env. The dashboard uses this
// to render an accurate blocking count for the delete-product flow
// without having to fetch every license row.
func (s *Service) CountsByProductStatus(ctx context.Context, accountID core.AccountID, env core.Environment, productID core.ProductID) (domain.LicenseStatusCounts, error) {
	var counts domain.LicenseStatusCounts
	err := s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
		product, err := s.products.GetByID(ctx, productID)
		if err != nil {
			return err
		}
		if product == nil {
			return core.NewAppError(core.ErrProductNotFound, "Product not found")
		}
		counts, err = s.licenses.CountsByProductStatus(ctx, productID)
		return err
	})
	if err != nil {
		return domain.LicenseStatusCounts{}, err
	}
	return counts, nil
}

// BulkRevokeForProduct atomically revokes every active or suspended
// license for the given product in the given env. Used by the
// dashboard to unblock product deletion when there are too many
// licenses to revoke individually through the bulk-action toolbar.
// Returns the number of licenses revoked.
func (s *Service) BulkRevokeForProduct(ctx context.Context, accountID core.AccountID, env core.Environment, productID core.ProductID) (int, error) {
	var count int
	err := s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
		product, err := s.products.GetByID(ctx, productID)
		if err != nil {
			return err
		}
		if product == nil {
			return core.NewAppError(core.ErrProductNotFound, "Product not found")
		}
		count, err = s.licenses.BulkRevokeByProduct(ctx, productID)
		return err
	})
	if err != nil {
		return 0, err
	}
	// We deliberately do NOT fan out N license.revoked webhooks here.
	// A bulk cleanup would otherwise drown subscribers in events
	// without giving them anything actionable they couldn't get from
	// the count itself. If aggregate cleanup notifications become
	// useful we can introduce a single license.bulk_revoked event.
	return count, nil
}

func (s *Service) Get(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID) (*domain.License, error) {
	var result *domain.License

	err := s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
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

func (s *Service) Revoke(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID) error {
	result, err := s.transitionStatus(ctx, accountID, env, licenseID,
		func(st core.LicenseStatus) bool { return st.CanRevoke() },
		core.LicenseStatusRevoked,
		"License cannot be revoked from current status",
	)
	if err != nil {
		return err
	}
	s.dispatchEvent(ctx, accountID, env, core.EventTypeLicenseRevoked, result)
	return nil
}

func (s *Service) Suspend(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID) (*domain.License, error) {
	result, err := s.transitionStatus(ctx, accountID, env, licenseID,
		func(st core.LicenseStatus) bool { return st.CanSuspend() },
		core.LicenseStatusSuspended,
		"License cannot be suspended from current status",
	)
	if err != nil {
		return nil, err
	}
	s.dispatchEvent(ctx, accountID, env, core.EventTypeLicenseSuspended, result)
	return result, nil
}

func (s *Service) Reinstate(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID) (*domain.License, error) {
	result, err := s.transitionStatus(ctx, accountID, env, licenseID,
		func(st core.LicenseStatus) bool { return st.CanReinstate() },
		core.LicenseStatusActive,
		"License cannot be reinstated from current status",
	)
	if err != nil {
		return nil, err
	}
	s.dispatchEvent(ctx, accountID, env, core.EventTypeLicenseReinstated, result)
	return result, nil
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

func (s *Service) Activate(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, req ActivateRequest) (*domain.Machine, error) {
	if err := ValidateFingerprint(req.Fingerprint); err != nil {
		return nil, err
	}

	var result *domain.Machine

	err := s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
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
			Environment: env,
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
	s.dispatchEvent(ctx, accountID, env, core.EventTypeMachineActivated, result)
	return result, nil
}

func (s *Service) Deactivate(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, req DeactivateRequest) error {
	if err := ValidateFingerprint(req.Fingerprint); err != nil {
		return err
	}

	err := s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
		return s.machines.DeleteByFingerprint(ctx, licenseID, req.Fingerprint)
	})
	if err != nil {
		return err
	}
	s.dispatchEvent(ctx, accountID, env, core.EventTypeMachineDeactivated, map[string]string{
		"license_id":  licenseID.String(),
		"fingerprint": req.Fingerprint,
	})
	return nil
}

func (s *Service) Heartbeat(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, req HeartbeatRequest) (*domain.Machine, error) {
	if err := ValidateFingerprint(req.Fingerprint); err != nil {
		return nil, err
	}

	var result *domain.Machine

	err := s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
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

func (s *Service) dispatchEvent(ctx context.Context, accountID core.AccountID, env core.Environment, eventType core.EventType, payload any) {
	if s.webhookSvc == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Error("webhook: failed to marshal event payload", "event", eventType, "error", err)
		return
	}
	s.webhookSvc.Dispatch(ctx, accountID, env, eventType, data)
}

// buildLicense constructs a domain.License from pre-generated values and a CreateRequest.
// It parses the license type, builds and signs the token, and returns the populated license.
func buildLicense(
	req CreateRequest,
	licenseID core.LicenseID,
	prefix, keyHash string,
	now time.Time,
	accountID core.AccountID,
	productID core.ProductID,
	validationTTL int,
	privKey ed25519.PrivateKey,
	env core.Environment,
) (*domain.License, error) {
	licenseType, err := core.ParseLicenseType(req.LicenseType)
	if err != nil {
		return nil, core.NewAppError(core.ErrValidationError, "Invalid license type")
	}

	payload := crypto.TokenPayload{
		Version:     1,
		ProductID:   productID.String(),
		LicenseID:   licenseID.String(),
		Type:        licenseType,
		Status:      core.LicenseStatusActive,
		MaxMachines: req.MaxMachines,
		IssuedAt:    now.Unix(),
		TTL:         validationTTL,
	}
	if req.Entitlements != nil {
		payload.Entitlements = *req.Entitlements
	}
	if req.ExpiresAt != nil {
		exp := req.ExpiresAt.Unix()
		payload.ExpiresAt = &exp
	}

	token, err := crypto.SignToken(payload, privKey)
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to sign license token")
	}

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
		Environment:   env,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	return license, nil
}

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
	env core.Environment,
	licenseID core.LicenseID,
	canTransition func(core.LicenseStatus) bool,
	target core.LicenseStatus,
	errMsg string,
) (*domain.License, error) {
	var result *domain.License

	err := s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
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
