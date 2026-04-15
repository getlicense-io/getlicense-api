package db

import (
	"context"
	"errors"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// scanAPIKey scans an API key row from a scannable (pgx.Row or pgx.Rows).
func scanAPIKey(s scannable) (domain.APIKey, error) {
	var k domain.APIKey
	var rawID, rawAccountID uuid.UUID
	var rawProductID *uuid.UUID
	var scope, env string
	err := s.Scan(
		&rawID, &rawAccountID, &rawProductID,
		&k.Prefix, &k.KeyHash, &scope, &k.Label,
		&env, &k.ExpiresAt, &k.CreatedAt,
	)
	if err != nil {
		return k, err
	}
	k.ID = core.APIKeyID(rawID)
	k.AccountID = core.AccountID(rawAccountID)
	k.Scope = core.APIKeyScope(scope)
	k.Environment = core.Environment(env)
	if rawProductID != nil {
		pid := core.ProductID(*rawProductID)
		k.ProductID = &pid
	}
	return k, nil
}

const apiKeyColumns = `id, account_id, product_id, prefix, key_hash, scope, label, environment, expires_at, created_at`

// APIKeyRepo implements domain.APIKeyRepository using PostgreSQL.
type APIKeyRepo struct {
	pool *pgxpool.Pool
}

var _ domain.APIKeyRepository = (*APIKeyRepo)(nil)

// NewAPIKeyRepo creates a new APIKeyRepo.
func NewAPIKeyRepo(pool *pgxpool.Pool) *APIKeyRepo {
	return &APIKeyRepo{pool: pool}
}

// Create inserts a new API key into the database.
func (r *APIKeyRepo) Create(ctx context.Context, key *domain.APIKey) error {
	q := conn(ctx, r.pool)

	var productID interface{}
	if key.ProductID != nil {
		productID = uuid.UUID(*key.ProductID)
	}

	_, err := q.Exec(ctx,
		`INSERT INTO api_keys (`+apiKeyColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		uuid.UUID(key.ID), uuid.UUID(key.AccountID), productID,
		key.Prefix, key.KeyHash, string(key.Scope), key.Label,
		string(key.Environment), key.ExpiresAt, key.CreatedAt,
	)
	return err
}

// GetByHash returns the API key matching the given hash, or nil if not found.
// This is a global query used for API key authentication.
func (r *APIKeyRepo) GetByHash(ctx context.Context, keyHash string) (*domain.APIKey, error) {
	q := conn(ctx, r.pool)
	k, err := scanAPIKey(q.QueryRow(ctx,
		`SELECT `+apiKeyColumns+` FROM api_keys WHERE key_hash = $1`,
		keyHash,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &k, nil
}

// ListByAccount returns API keys for the current RLS account in
// the given environment. RLS narrows to the account; env is filtered
// in SQL because the api_keys RLS policy intentionally permits
// cross-env writes (a live key is allowed to create/delete a test key).
func (r *APIKeyRepo) ListByAccount(ctx context.Context, env core.Environment, cursor core.Cursor, limit int) ([]domain.APIKey, bool, error) {
	q := conn(ctx, r.pool)

	var rows pgx.Rows
	var err error
	if cursor.IsZero() {
		rows, err = q.Query(ctx,
			`SELECT `+apiKeyColumns+` FROM api_keys
			 WHERE environment = $1
			 ORDER BY created_at DESC, id DESC LIMIT $2`,
			string(env), limit+1,
		)
	} else {
		rows, err = q.Query(ctx,
			`SELECT `+apiKeyColumns+` FROM api_keys
			 WHERE environment = $1
			   AND (created_at, id) < ($2, $3)
			 ORDER BY created_at DESC, id DESC LIMIT $4`,
			string(env), cursor.CreatedAt, cursor.ID, limit+1,
		)
	}
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	out := make([]domain.APIKey, 0, limit+1)
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

// Delete removes the API key with the given ID.
// Returns an error if the API key does not exist.
func (r *APIKeyRepo) Delete(ctx context.Context, id core.APIKeyID) error {
	q := conn(ctx, r.pool)
	tag, err := q.Exec(ctx, `DELETE FROM api_keys WHERE id = $1`, uuid.UUID(id))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.NewAppError(core.ErrAPIKeyNotFound, "API key not found")
	}
	return nil
}
