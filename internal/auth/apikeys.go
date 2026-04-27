package auth

import (
	"context"
	"net/netip"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// --- API keys ---

// CreateAPIKey mints a new API key for the target account. Scope defaults
// to account_wide; product-scoped keys must additionally include a
// product_id belonging to the target account (not a different tenant —
// RLS-filtered to prevent existence leaks across accounts).
func (s *Service) CreateAPIKey(
	ctx context.Context,
	targetAccountID core.AccountID,
	env core.Environment,
	createdByIdentityID *core.IdentityID,
	createdByAPIKeyID *core.APIKeyID,
	req CreateAPIKeyRequest,
) (*CreateAPIKeyResult, error) {
	reqEnv, err := core.ParseEnvironment(req.Environment)
	if err != nil {
		return nil, core.NewAppError(core.ErrValidationError, "Invalid environment slug")
	}

	if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now().UTC()) {
		return nil, core.NewAppError(core.ErrValidationError,
			"expires_at must be in the future")
	}
	for _, raw := range req.IPAllowlist {
		if _, err := netip.ParsePrefix(raw); err != nil {
			return nil, core.NewAppError(core.ErrValidationError, "ip_allowlist entries must be CIDR prefixes")
		}
	}

	scope := req.Scope
	if scope == "" {
		scope = core.APIKeyScopeAccountWide
	}
	switch scope {
	case core.APIKeyScopeAccountWide:
		if req.ProductID != nil {
			return nil, core.NewAppError(core.ErrValidationError,
				"product_id must be omitted when scope is account_wide")
		}
	case core.APIKeyScopeProduct:
		if req.ProductID == nil {
			return nil, core.NewAppError(core.ErrValidationError,
				"product_id is required when scope is product")
		}
	default:
		return nil, core.NewAppError(core.ErrValidationError,
			"scope must be 'account_wide' or 'product'")
	}

	var result *CreateAPIKeyResult
	err = s.txManager.WithTargetAccount(ctx, targetAccountID, env, func(ctx context.Context) error {
		if scope == core.APIKeyScopeProduct {
			// Product existence check runs inside the target-account tx
			// so RLS filters rows to THIS tenant. A product belonging to
			// another tenant resolves to nil here; collapsed to 404 so
			// the caller cannot probe product existence across accounts.
			prod, perr := s.products.GetByID(ctx, *req.ProductID)
			if perr != nil {
				return perr
			}
			if prod == nil {
				return core.NewAppError(core.ErrProductNotFound, "Product not found")
			}
		}
		apiKey, rawKey, cerr := s.createAPIKeyRecord(ctx, targetAccountID, reqEnv, scope, req.ProductID, req.Label, req.ExpiresAt, createdByIdentityID, createdByAPIKeyID, req.Permissions, req.IPAllowlist)
		if cerr != nil {
			return cerr
		}
		result = &CreateAPIKeyResult{APIKey: apiKey, RawKey: rawKey}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) ListAPIKeys(ctx context.Context, targetAccountID core.AccountID, env core.Environment, cursor core.Cursor, limit int) ([]domain.APIKey, bool, error) {
	var keys []domain.APIKey
	var hasMore bool
	err := s.txManager.WithTargetAccount(ctx, targetAccountID, env, func(ctx context.Context) error {
		var err error
		keys, hasMore, err = s.apiKeys.ListByAccount(ctx, env, cursor, limit)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return keys, hasMore, nil
}

func (s *Service) DeleteAPIKey(ctx context.Context, targetAccountID core.AccountID, env core.Environment, id core.APIKeyID, revokedByIdentityID *core.IdentityID) error {
	reason := "user_requested"
	return s.txManager.WithTargetAccount(ctx, targetAccountID, env, func(ctx context.Context) error {
		return s.apiKeys.Revoke(ctx, id, revokedByIdentityID, &reason, time.Now().UTC())
	})
}
