package licensing

import (
	"context"
	"encoding/json"
	"time"

	"log/slog"

	"github.com/getlicense-io/getlicense-api/internal/audit"
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/policy"
)

// ListMachines returns machines for licenseID, cursor-paginated, with
// optional status filter and a grantee gate.
//
// statusFilter is validated against core.MachineStatus; an unknown
// value returns ErrValidationError (422). Empty string means "no
// filter".
//
// callerGrantID is the caller's GrantID when invoked from the
// /v1/grants/:grant_id/... routes (populated by ResolveGrant
// middleware), nil for vendor direct calls. When non-nil, the license
// MUST have been created under THAT grant — otherwise return 404 to
// avoid leaking the license's existence to a grantee asking about a
// license that isn't theirs.
func (s *Service) ListMachines(
	ctx context.Context,
	accountID core.AccountID,
	env core.Environment,
	licenseID core.LicenseID,
	statusFilter string,
	cursor core.Cursor,
	limit int,
	callerGrantID *core.GrantID,
) ([]domain.Machine, bool, error) {
	// Validate status BEFORE opening the tx. An unknown value is a
	// caller bug, not a data-access failure.
	if statusFilter != "" && !core.MachineStatus(statusFilter).IsValid() {
		return nil, false, core.NewAppError(core.ErrValidationError,
			"Invalid status filter; expected active|stale|dead")
	}

	var rows []domain.Machine
	var hasMore bool
	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		lic, err := s.requireLicense(ctx, licenseID)
		if err != nil {
			return err
		}
		// Grantee gate: grantee caller may only see machines on
		// licenses created under THEIR grant. 404 (not 403) so we do
		// not leak the license's existence across grant boundaries.
		if callerGrantID != nil && (lic.GrantID == nil || *lic.GrantID != *callerGrantID) {
			return core.NewAppError(core.ErrLicenseNotFound, "License not found")
		}
		var e error
		rows, hasMore, e = s.machines.ListByLicense(ctx, licenseID, statusFilter, cursor, limit)
		return e
	})
	if err != nil {
		return nil, false, err
	}
	return rows, hasMore, nil
}

// Activate registers a machine for a license and issues a signed gl2
// lease token. The request is idempotent per (license, fingerprint):
// re-activating the same fingerprint reuses the existing machine row
// and overwrites its hostname/metadata/lease state. Re-activating a
// dead fingerprint (lease grace window elapsed) resurrects it and
// resets status to active — the audit row is preserved. The max
// machines cap is enforced against CountAliveByLicense (active + stale)
// excluding the fingerprint being activated so an idempotent re-activate
// doesn't double-count.
func (s *Service) Activate(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, req ActivateRequest, attr audit.Attribution) (*ActivateResult, error) {
	if !isValidFingerprint(req.Fingerprint) {
		return nil, core.NewAppError(core.ErrMachineInvalidFingerprint, "fingerprint must be 1-256 chars from [A-Za-z0-9+/=_-]")
	}

	var result *ActivateResult

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		license, err := s.requireLicenseForUpdate(ctx, licenseID)
		if err != nil {
			return err
		}

		// Terminal or hold statuses short-circuit before we even look at
		// the policy — they already represent an explicit operator or
		// scheduler decision that overrides the policy's expiration view.
		switch license.Status {
		case core.LicenseStatusRevoked:
			return core.NewAppError(core.ErrLicenseRevoked, "License has been revoked")
		case core.LicenseStatusSuspended:
			return core.NewAppError(core.ErrLicenseSuspended, "License is suspended")
		case core.LicenseStatusInactive:
			return core.NewAppError(core.ErrLicenseInactive, "License is inactive")
		case core.LicenseStatusExpired:
			return core.NewAppError(core.ErrLicenseExpired, "License has expired")
		}

		p, err := s.policies.Get(ctx, license.PolicyID)
		if err != nil {
			return err
		}
		if p == nil {
			return core.NewAppError(core.ErrPolicyNotFound, "policy not found")
		}
		eff := policy.Resolve(p, license.Overrides)

		// Policy-driven expiration decision. For REVOKE_ACCESS this
		// returns invalid; for MAINTAIN/RESTRICT_ACCESS callers decide
		// at validate time — activation still refuses past-expiry to
		// avoid minting new leases on a stale license.
		if dec := policy.EvaluateExpiration(eff, license.ExpiresAt); !dec.Valid {
			return core.NewAppError(dec.Code, "License has expired")
		}

		now := time.Now().UTC()

		// FROM_FIRST_ACTIVATION: stamp first_activated_at and (if a
		// duration is set) compute expires_at on first hit only. The
		// same tx persists the stamp so a concurrent retry sees it.
		if license.FirstActivatedAt == nil && p.ExpirationBasis == core.ExpirationBasisFromFirstActivation {
			license.FirstActivatedAt = &now
			if eff.DurationSeconds != nil {
				exp := now.Add(time.Duration(*eff.DurationSeconds) * time.Second)
				license.ExpiresAt = &exp
			}
			if err := s.licenses.Update(ctx, license); err != nil {
				return err
			}
		}

		// Check for an existing row for this (license, fingerprint).
		// A hit means either an idempotent re-activate or a resurrection
		// of a dead machine — both reuse the ID so the audit row is kept.
		existing, err := s.machines.GetByFingerprint(ctx, licenseID, req.Fingerprint)
		if err != nil {
			return err
		}

		// Enforce max_machines against alive (active+stale) rows, but
		// only when the activation is for a NEW fingerprint. An idempotent
		// re-activate or a resurrection of a dead machine under an
		// existing fingerprint never needs a cap check — the row either
		// already counts (active/stale) or is dead and doesn't.
		if eff.MaxMachines != nil && existing == nil {
			alive, err := s.machines.CountAliveByLicense(ctx, licenseID)
			if err != nil {
				return err
			}
			if alive >= *eff.MaxMachines {
				return core.NewAppError(core.ErrMachineLimitExceeded, "Machine limit exceeded")
			}
		}

		var metadata json.RawMessage
		if req.Metadata != nil {
			metadata = *req.Metadata
		}

		leaseExp := ComputeLeaseExpiresAt(eff, license.ExpiresAt, now)

		var machine *domain.Machine
		if existing != nil {
			machine = existing
			machine.Hostname = req.Hostname
			machine.Metadata = metadata
		} else {
			machine = &domain.Machine{
				ID:          core.NewMachineID(),
				AccountID:   accountID,
				LicenseID:   licenseID,
				Fingerprint: req.Fingerprint,
				Hostname:    req.Hostname,
				Metadata:    metadata,
				Environment: env,
				CreatedAt:   now,
			}
		}
		machine.LeaseIssuedAt = now
		machine.LeaseExpiresAt = leaseExp
		machine.LastCheckinAt = now
		machine.Status = core.MachineStatusActive

		if err := s.machines.UpsertActivation(ctx, machine); err != nil {
			return err
		}

		entCodes, err := s.entitlements.ResolveEffective(ctx, license.ID)
		if err != nil {
			return err
		}

		privKey, err := s.decryptProductPrivateKey(ctx, license.ProductID)
		if err != nil {
			return err
		}
		claims := BuildLeaseClaims(BuildLeaseClaimsInput{
			LicenseID:        license.ID,
			ProductID:        license.ProductID,
			PolicyID:         license.PolicyID,
			MachineID:        machine.ID,
			Fingerprint:      machine.Fingerprint,
			LicenseStatus:    license.Status,
			LicenseExpiresAt: license.ExpiresAt,
			LeaseIssuedAt:    machine.LeaseIssuedAt,
			LeaseExpiresAt:   machine.LeaseExpiresAt,
			Effective:        eff,
			Entitlements:     entCodes,
		})
		leaseToken, err := crypto.SignLeaseToken(claims, privKey)
		if err != nil {
			return core.NewAppError(core.ErrLeaseSignFailed, "failed to sign lease token")
		}

		result = &ActivateResult{
			Machine:     machine,
			LeaseToken:  leaseToken,
			LeaseClaims: claims,
		}

		if s.audit != nil {
			payload, _ := json.Marshal(map[string]any{
				"machine_id":       result.Machine.ID,
				"license_id":       result.Machine.LicenseID,
				"fingerprint":      result.Machine.Fingerprint,
				"lease_expires_at": result.Machine.LeaseExpiresAt,
			})
			if err := s.audit.Record(ctx, audit.EventFrom(attr, core.EventTypeMachineActivated, "machine", result.Machine.ID.String(), payload)); err != nil {
				slog.Error("audit: failed to record event", "event", core.EventTypeMachineActivated, "error", err)
			}
		}
		return nil
	})
	return result, err
}

// Checkin renews a machine's lease. Differs from Activate:
//   - Rejects if the machine is dead (caller must Activate to resurrect).
//   - Does NOT recheck max_machines (existing machines are already counted).
//   - Updates lease_issued_at + lease_expires_at + last_checkin_at and
//     transitions stale → active.
func (s *Service) Checkin(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, fingerprint string, attr audit.Attribution) (*CheckinResult, error) {
	if !isValidFingerprint(fingerprint) {
		return nil, core.NewAppError(core.ErrMachineInvalidFingerprint, "fingerprint must be 1-256 chars from [A-Za-z0-9+/=_-]")
	}

	var result *CheckinResult

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		license, err := s.requireLicenseForUpdate(ctx, licenseID)
		if err != nil {
			return err
		}

		switch license.Status {
		case core.LicenseStatusRevoked:
			return core.NewAppError(core.ErrLicenseRevoked, "License has been revoked")
		case core.LicenseStatusSuspended:
			return core.NewAppError(core.ErrLicenseSuspended, "License is suspended")
		case core.LicenseStatusInactive:
			return core.NewAppError(core.ErrLicenseInactive, "License is inactive")
		case core.LicenseStatusExpired:
			return core.NewAppError(core.ErrLicenseExpired, "License has expired")
		}

		p, err := s.policies.Get(ctx, license.PolicyID)
		if err != nil {
			return err
		}
		if p == nil {
			return core.NewAppError(core.ErrPolicyNotFound, "policy not found")
		}
		eff := policy.Resolve(p, license.Overrides)

		if dec := policy.EvaluateExpiration(eff, license.ExpiresAt); !dec.Valid {
			return core.NewAppError(dec.Code, "License has expired")
		}

		machine, err := s.machines.GetByFingerprint(ctx, licenseID, fingerprint)
		if err != nil {
			return err
		}
		if machine == nil {
			return core.NewAppError(core.ErrMachineNotFound, "machine not found for license")
		}
		if machine.Status == core.MachineStatusDead {
			return core.NewAppError(core.ErrMachineDead, "machine is dead — re-activate to resurrect")
		}

		now := time.Now().UTC()
		machine.LeaseIssuedAt = now
		machine.LeaseExpiresAt = ComputeLeaseExpiresAt(eff, license.ExpiresAt, now)
		machine.LastCheckinAt = now
		machine.Status = core.MachineStatusActive

		if err := s.machines.RenewLease(ctx, machine); err != nil {
			return err
		}

		entCodes, err := s.entitlements.ResolveEffective(ctx, license.ID)
		if err != nil {
			return err
		}

		privKey, err := s.decryptProductPrivateKey(ctx, license.ProductID)
		if err != nil {
			return err
		}
		claims := BuildLeaseClaims(BuildLeaseClaimsInput{
			LicenseID:        license.ID,
			ProductID:        license.ProductID,
			PolicyID:         license.PolicyID,
			MachineID:        machine.ID,
			Fingerprint:      machine.Fingerprint,
			LicenseStatus:    license.Status,
			LicenseExpiresAt: license.ExpiresAt,
			LeaseIssuedAt:    machine.LeaseIssuedAt,
			LeaseExpiresAt:   machine.LeaseExpiresAt,
			Effective:        eff,
			Entitlements:     entCodes,
		})
		leaseToken, err := crypto.SignLeaseToken(claims, privKey)
		if err != nil {
			return core.NewAppError(core.ErrLeaseSignFailed, "failed to sign lease token")
		}

		result = &CheckinResult{
			Machine:     machine,
			LeaseToken:  leaseToken,
			LeaseClaims: claims,
		}

		if s.audit != nil {
			payload, _ := json.Marshal(map[string]any{
				"machine_id":       result.Machine.ID,
				"license_id":       result.Machine.LicenseID,
				"fingerprint":      result.Machine.Fingerprint,
				"lease_expires_at": result.Machine.LeaseExpiresAt,
			})
			if err := s.audit.Record(ctx, audit.EventFrom(attr, core.EventTypeMachineCheckedIn, "machine", result.Machine.ID.String(), payload)); err != nil {
				slog.Error("audit: failed to record event", "event", core.EventTypeMachineCheckedIn, "error", err)
			}
		}
		return nil
	})
	return result, err
}

func (s *Service) Deactivate(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, req DeactivateRequest, attr audit.Attribution) error {
	if err := ValidateFingerprint(req.Fingerprint); err != nil {
		return err
	}

	return s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		// Load the license purely for the product-scope gate. Deactivate
		// otherwise goes straight to the machines table, so without this
		// lookup a product-scoped API key could deactivate a machine on
		// a license outside its scope. Non-locking — we don't mutate the
		// license row.
		if _, err := s.requireLicense(ctx, licenseID); err != nil {
			return err
		}
		if err := s.machines.DeleteByFingerprint(ctx, licenseID, req.Fingerprint); err != nil {
			return err
		}

		if s.audit != nil {
			payload, _ := json.Marshal(map[string]string{
				"license_id":  licenseID.String(),
				"fingerprint": req.Fingerprint,
			})
			if err := s.audit.Record(ctx, audit.EventFrom(attr, core.EventTypeMachineDeactivated, "machine", licenseID.String(), payload)); err != nil {
				slog.Error("audit: failed to record event", "event", core.EventTypeMachineDeactivated, "error", err)
			}
		}
		return nil
	})
}
