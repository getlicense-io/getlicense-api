package db

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	sqlcgen "github.com/getlicense-io/getlicense-api/internal/db/sqlc/gen"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// APIKeyRepo implements domain.APIKeyRepository against sqlc-generated
// queries. API key creation leaves unique-violation classification out
// on purpose: a key_hash collision is an HMAC collision on random input,
// i.e. a crypto-level anomaly, not something we want to surface as a
// typed error.
type APIKeyRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.APIKeyRepository = (*APIKeyRepo)(nil)

// NewAPIKeyRepo creates a new APIKeyRepo.
func NewAPIKeyRepo(pool *pgxpool.Pool) *APIKeyRepo {
	return &APIKeyRepo{pool: pool, q: sqlcgen.New()}
}

// apiKeyFromRow translates a sqlcgen.ApiKey (note sqlc's initialism —
// the table is api_keys, so the generated struct is ApiKey) to the
// domain.APIKey. ProductID is nullable at both the SQL and domain
// levels; nullableIDFromPgUUID collapses pgtype.UUID.Valid=false to nil.
func apiKeyFromRow(row sqlcgen.ApiKey) domain.APIKey {
	var lastUsedIP *string
	if row.LastUsedIp != nil {
		s := row.LastUsedIp.String()
		lastUsedIP = &s
	}
	ipAllowlist := make([]string, len(row.IpAllowlist))
	for i, cidr := range row.IpAllowlist {
		ipAllowlist[i] = cidr.String()
	}
	return domain.APIKey{
		ID:                    idFromPgUUID[core.APIKeyID](row.ID),
		AccountID:             idFromPgUUID[core.AccountID](row.AccountID),
		ProductID:             nullableIDFromPgUUID[core.ProductID](row.ProductID),
		Prefix:                row.Prefix,
		KeyHash:               row.KeyHash,
		Scope:                 core.APIKeyScope(row.Scope),
		Label:                 row.Label,
		Environment:           core.Environment(row.Environment),
		ExpiresAt:             row.ExpiresAt,
		CreatedAt:             row.CreatedAt,
		LastUsedAt:            row.LastUsedAt,
		LastUsedIP:            lastUsedIP,
		LastUsedUserAgentHash: row.LastUsedUserAgentHash,
		CreatedByIdentityID:   nullableIDFromPgUUID[core.IdentityID](row.CreatedByIdentityID),
		CreatedByAPIKeyID:     nullableIDFromPgUUID[core.APIKeyID](row.CreatedByApiKeyID),
		RevokedAt:             row.RevokedAt,
		RevokedByIdentityID:   nullableIDFromPgUUID[core.IdentityID](row.RevokedByIdentityID),
		RevokedReason:         row.RevokedReason,
		Permissions:           row.Permissions,
		IPAllowlist:           ipAllowlist,
	}
}

// Create inserts a new API key. No unique-violation classification —
// see the package doc on APIKeyRepo.
func (r *APIKeyRepo) Create(ctx context.Context, key *domain.APIKey) error {
	permissions := key.Permissions
	if permissions == nil {
		permissions = []string{}
	}
	ipAllowlist := make([]netip.Prefix, len(key.IPAllowlist))
	for i, raw := range key.IPAllowlist {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return err
		}
		ipAllowlist[i] = prefix
	}
	return r.q.CreateAPIKey(ctx, conn(ctx, r.pool), sqlcgen.CreateAPIKeyParams{
		ID:                  pgUUIDFromID(key.ID),
		AccountID:           pgUUIDFromID(key.AccountID),
		ProductID:           pgUUIDFromIDPtr(key.ProductID),
		Prefix:              key.Prefix,
		KeyHash:             key.KeyHash,
		Scope:               string(key.Scope),
		Label:               key.Label,
		Environment:         string(key.Environment),
		ExpiresAt:           key.ExpiresAt,
		CreatedAt:           key.CreatedAt,
		CreatedByIdentityID: pgUUIDFromIDPtr(key.CreatedByIdentityID),
		CreatedByApiKeyID:   pgUUIDFromIDPtr(key.CreatedByAPIKeyID),
		Permissions:         permissions,
		IpAllowlist:         ipAllowlist,
	})
}

// GetByHash returns the API key matching the given hash, or nil if not
// found. This is the global lookup used by API-key authentication; RLS
// is bypassed here because the acting account isn't known until after
// the lookup resolves.
func (r *APIKeyRepo) GetByHash(ctx context.Context, keyHash string) (*domain.APIKey, error) {
	row, err := r.q.GetAPIKeyByHash(ctx, conn(ctx, r.pool), keyHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	k := apiKeyFromRow(row)
	return &k, nil
}

// ListByAccount returns API keys for the current RLS account in the
// given environment, paginated by (created_at DESC, id DESC). RLS
// narrows to the account; env is filtered at SQL because the api_keys
// RLS policy intentionally permits cross-env visibility within an
// account so a live key can manage test keys.
func (r *APIKeyRepo) ListByAccount(ctx context.Context, env core.Environment, cursor core.Cursor, limit int) ([]domain.APIKey, bool, error) {
	ts, id := cursorParams(cursor)

	// sqlc inferred CursorID as pgtype.UUID (non-pointer) because the
	// row-comparison context doesn't give it a column to key off. The
	// query guards on cursor_ts IS NULL first, so passing a zero-value
	// pgtype.UUID when the cursor is unset is safe — the uuid narg is
	// never dereferenced on that branch.
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}

	rows, err := r.q.ListAPIKeysByAccountAndEnv(ctx, conn(ctx, r.pool), sqlcgen.ListAPIKeysByAccountAndEnvParams{
		Environment:  string(env),
		CursorTs:     ts,
		CursorID:     cursorID,
		LimitPlusOne: int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}

	out := make([]domain.APIKey, 0, len(rows))
	for _, row := range rows {
		out = append(out, apiKeyFromRow(row))
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}

// Delete removes the API key with the given id. Returns
// core.ErrAPIKeyNotFound when no row was affected (either the id does
// not exist or RLS filtered it out).
func (r *APIKeyRepo) RecordUse(ctx context.Context, id core.APIKeyID, ip, userAgentHash *string, usedAt time.Time) error {
	var parsedIP *netip.Addr
	if ip != nil {
		addr, err := netip.ParseAddr(*ip)
		if err != nil {
			return err
		}
		parsedIP = &addr
	}
	return r.q.RecordAPIKeyUse(ctx, conn(ctx, r.pool), sqlcgen.RecordAPIKeyUseParams{
		ID:                    pgUUIDFromID(id),
		LastUsedAt:            usedAt,
		LastUsedIp:            parsedIP,
		LastUsedUserAgentHash: userAgentHash,
	})
}

// Revoke marks the API key revoked. Returns core.ErrAPIKeyNotFound
// when no unrevoked row was affected.
func (r *APIKeyRepo) Revoke(ctx context.Context, id core.APIKeyID, revokedByIdentityID *core.IdentityID, reason *string, revokedAt time.Time) error {
	n, err := r.q.RevokeAPIKey(ctx, conn(ctx, r.pool), sqlcgen.RevokeAPIKeyParams{
		ID:                  pgUUIDFromID(id),
		RevokedAt:           revokedAt,
		RevokedByIdentityID: pgUUIDFromIDPtr(revokedByIdentityID),
		RevokedReason:       reason,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return core.NewAppError(core.ErrAPIKeyNotFound, "API key not found")
	}
	return nil
}
