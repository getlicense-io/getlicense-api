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
	var scope string
	err := s.Scan(
		&rawID, &rawAccountID, &rawProductID,
		&k.Prefix, &k.KeyHash, &scope, &k.Label,
		&k.Environment, &k.ExpiresAt, &k.CreatedAt,
	)
	if err != nil {
		return k, err
	}
	k.ID = core.APIKeyID(rawID)
	k.AccountID = core.AccountID(rawAccountID)
	k.Scope = core.APIKeyScope(scope)
	if rawProductID != nil {
		pid := core.ProductID(*rawProductID)
		k.ProductID = &pid
	}
	return k, nil
}

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
		`INSERT INTO api_keys (id, account_id, product_id, prefix, key_hash, scope, label, environment, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		uuid.UUID(key.ID), uuid.UUID(key.AccountID), productID,
		key.Prefix, key.KeyHash, string(key.Scope), key.Label,
		key.Environment, key.ExpiresAt, key.CreatedAt,
	)
	return err
}

// GetByHash returns the API key matching the given hash, or nil if not found.
// This is a global query used for API key authentication.
func (r *APIKeyRepo) GetByHash(ctx context.Context, keyHash string) (*domain.APIKey, error) {
	q := conn(ctx, r.pool)
	k, err := scanAPIKey(q.QueryRow(ctx,
		`SELECT id, account_id, product_id, prefix, key_hash, scope, label, environment, expires_at, created_at
		 FROM api_keys WHERE key_hash = $1`,
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

// ListByAccount returns a paginated list of API keys and the total count.
func (r *APIKeyRepo) ListByAccount(ctx context.Context, limit, offset int) ([]domain.APIKey, int, error) {
	q := conn(ctx, r.pool)

	var total int
	if err := q.QueryRow(ctx, `SELECT COUNT(*) FROM api_keys`).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := q.Query(ctx,
		`SELECT id, account_id, product_id, prefix, key_hash, scope, label, environment, expires_at, created_at
		 FROM api_keys ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var keys []domain.APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, 0, err
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return keys, total, nil
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
		return core.NewAppError(core.ErrValidationError, "API key not found")
	}
	return nil
}
