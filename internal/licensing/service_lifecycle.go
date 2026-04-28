package licensing

import (
	"context"
	"encoding/json"

	"log/slog"

	"github.com/getlicense-io/getlicense-api/internal/audit"
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

func (s *Service) Revoke(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, attr audit.Attribution) error {
	_, err := s.transitionStatus(ctx, accountID, env, licenseID,
		func(st core.LicenseStatus) bool { return st.CanRevoke() },
		core.LicenseStatusRevoked,
		"License cannot be revoked from current status",
		attr, core.EventTypeLicenseRevoked,
	)
	return err
}

func (s *Service) Suspend(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, attr audit.Attribution) (*domain.License, error) {
	return s.transitionStatus(ctx, accountID, env, licenseID,
		func(st core.LicenseStatus) bool { return st.CanSuspend() },
		core.LicenseStatusSuspended,
		"License cannot be suspended from current status",
		attr, core.EventTypeLicenseSuspended,
	)
}

func (s *Service) Reinstate(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, attr audit.Attribution) (*domain.License, error) {
	return s.transitionStatus(ctx, accountID, env, licenseID,
		func(st core.LicenseStatus) bool { return st.CanReinstate() },
		core.LicenseStatusActive,
		"License cannot be reinstated from current status",
		attr, core.EventTypeLicenseReinstated,
	)
}

// transitionStatus is the shared implementation for Revoke, Suspend, and Reinstate.
// The audit record is written inside the tx so it shares the mutation's RLS context
// and is atomic with the status change.
func (s *Service) transitionStatus(
	ctx context.Context,
	accountID core.AccountID,
	env core.Environment,
	licenseID core.LicenseID,
	canTransition func(core.LicenseStatus) bool,
	target core.LicenseStatus,
	errMsg string,
	attr audit.Attribution,
	eventType core.EventType,
) (*domain.License, error) {
	var result *domain.License

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		license, err := s.requireLicense(ctx, licenseID)
		if err != nil {
			return err
		}
		if !canTransition(license.Status) {
			// F-015: emit a state-specific error code so clients can
			// distinguish "illegal transition" from generic validation.
			// The dashboard uses the code to decide whether to show a
			// form error (validation_error) or a state error (this).
			return core.NewAppError(licenseInvalidTransitionCode(license.Status), errMsg)
		}
		updatedAt, err := s.licenses.UpdateStatus(ctx, licenseID, license.Status, target)
		if err != nil {
			return err
		}
		license.Status = target
		license.UpdatedAt = updatedAt
		result = license

		if s.audit != nil {
			payload, _ := json.Marshal(result)
			if err := s.audit.Record(ctx, audit.EventFrom(attr, eventType, "license", result.ID.String(), payload)); err != nil {
				slog.Error("audit: failed to record event", "event", eventType, "error", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// licenseInvalidTransitionCode returns the typed error code for a
// refused state transition. When the current status has a dedicated
// code (revoked/suspended/expired/inactive) we use it so clients see
// license_revoked rather than the generic license_invalid_transition.
func licenseInvalidTransitionCode(current core.LicenseStatus) core.ErrorCode {
	switch current {
	case core.LicenseStatusRevoked:
		return core.ErrLicenseRevoked
	case core.LicenseStatusSuspended:
		return core.ErrLicenseSuspended
	case core.LicenseStatusExpired:
		return core.ErrLicenseExpired
	case core.LicenseStatusInactive:
		return core.ErrLicenseInactive
	default:
		return core.ErrLicenseInvalidTransition
	}
}
