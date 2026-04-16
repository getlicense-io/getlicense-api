package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// domainEventColumns lists the 16 columns used for INSERT statements.
const domainEventColumns = `id, account_id, environment, event_type, resource_type, resource_id, acting_account_id, identity_id, actor_label, actor_kind, api_key_id, grant_id, request_id, ip_address, payload, created_at`

// domainEventSelectColumns is the same list but with ip_address::text
// so pgx scans the inet value into a Go *string.
const domainEventSelectColumns = `id, account_id, environment, event_type, resource_type, resource_id, acting_account_id, identity_id, actor_label, actor_kind, api_key_id, grant_id, request_id, ip_address::text, payload, created_at`

// scanDomainEvent reads a single domain_event row from a scannable.
func scanDomainEvent(s scannable) (domain.DomainEvent, error) {
	var e domain.DomainEvent
	var rawID, rawAccountID uuid.UUID
	var envStr, eventType, resourceType, actorLabel, actorKind string
	var rawActingAccountID, rawIdentityID, rawAPIKeyID, rawGrantID *uuid.UUID
	var payload []byte

	err := s.Scan(
		&rawID, &rawAccountID, &envStr,
		&eventType, &resourceType, &e.ResourceID,
		&rawActingAccountID, &rawIdentityID,
		&actorLabel, &actorKind,
		&rawAPIKeyID, &rawGrantID,
		&e.RequestID, &e.IPAddress,
		&payload, &e.CreatedAt,
	)
	if err != nil {
		return e, err
	}

	e.ID = core.DomainEventID(rawID)
	e.AccountID = core.AccountID(rawAccountID)
	e.Environment = core.Environment(envStr)
	e.EventType = core.EventType(eventType)
	e.ResourceType = resourceType
	e.ActorLabel = actorLabel
	e.ActorKind = core.ActorKind(actorKind)

	if rawActingAccountID != nil {
		aid := core.AccountID(*rawActingAccountID)
		e.ActingAccountID = &aid
	}
	if rawIdentityID != nil {
		iid := core.IdentityID(*rawIdentityID)
		e.IdentityID = &iid
	}
	if rawAPIKeyID != nil {
		kid := core.APIKeyID(*rawAPIKeyID)
		e.APIKeyID = &kid
	}
	if rawGrantID != nil {
		gid := core.GrantID(*rawGrantID)
		e.GrantID = &gid
	}

	if len(payload) > 0 {
		e.Payload = json.RawMessage(payload)
	} else {
		e.Payload = json.RawMessage(`{}`)
	}

	return e, nil
}

// DomainEventRepo implements domain.DomainEventRepository using PostgreSQL.
type DomainEventRepo struct {
	pool *pgxpool.Pool
}

var _ domain.DomainEventRepository = (*DomainEventRepo)(nil)

// NewDomainEventRepo creates a new DomainEventRepo.
func NewDomainEventRepo(pool *pgxpool.Pool) *DomainEventRepo {
	return &DomainEventRepo{pool: pool}
}

// Create inserts a new domain event. Nil payload is coerced to {}.
func (r *DomainEventRepo) Create(ctx context.Context, e *domain.DomainEvent) error {
	q := conn(ctx, r.pool)

	if e.Payload == nil {
		e.Payload = json.RawMessage(`{}`)
	}

	var rawActingAccountID, rawIdentityID, rawAPIKeyID, rawGrantID *uuid.UUID
	if e.ActingAccountID != nil {
		u := uuid.UUID(*e.ActingAccountID)
		rawActingAccountID = &u
	}
	if e.IdentityID != nil {
		u := uuid.UUID(*e.IdentityID)
		rawIdentityID = &u
	}
	if e.APIKeyID != nil {
		u := uuid.UUID(*e.APIKeyID)
		rawAPIKeyID = &u
	}
	if e.GrantID != nil {
		u := uuid.UUID(*e.GrantID)
		rawGrantID = &u
	}

	_, err := q.Exec(ctx,
		`INSERT INTO domain_events (`+domainEventColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		uuid.UUID(e.ID), uuid.UUID(e.AccountID), string(e.Environment),
		string(e.EventType), e.ResourceType, e.ResourceID,
		rawActingAccountID, rawIdentityID,
		e.ActorLabel, string(e.ActorKind),
		rawAPIKeyID, rawGrantID,
		e.RequestID, e.IPAddress,
		e.Payload, e.CreatedAt,
	)
	return err
}

// Get returns the domain event with the given ID, or (nil, nil) on miss.
func (r *DomainEventRepo) Get(ctx context.Context, id core.DomainEventID) (*domain.DomainEvent, error) {
	q := conn(ctx, r.pool)
	e, err := scanDomainEvent(q.QueryRow(ctx,
		`SELECT `+domainEventSelectColumns+` FROM domain_events WHERE id = $1`,
		uuid.UUID(id),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &e, nil
}

// buildDomainEventFilterClause returns a WHERE fragment and args for
// the optional filters. argStart lets callers compose after their own
// placeholders (e.g. cursor args).
func buildDomainEventFilterClause(f domain.DomainEventFilter, argStart int) (string, []any) {
	var clauses []string
	var args []any
	next := argStart

	if f.ResourceType != "" {
		clauses = append(clauses, fmt.Sprintf("resource_type = $%d", next))
		args = append(args, f.ResourceType)
		next++
	}
	if f.ResourceID != "" {
		clauses = append(clauses, fmt.Sprintf("resource_id = $%d", next))
		args = append(args, f.ResourceID)
		next++
	}
	if f.EventType != "" {
		clauses = append(clauses, fmt.Sprintf("event_type = $%d", next))
		args = append(args, string(f.EventType))
		next++
	}
	if f.IdentityID != nil {
		clauses = append(clauses, fmt.Sprintf("identity_id = $%d", next))
		args = append(args, uuid.UUID(*f.IdentityID))
		next++
	}
	if f.GrantID != nil {
		clauses = append(clauses, fmt.Sprintf("grant_id = $%d", next))
		args = append(args, uuid.UUID(*f.GrantID))
		next++
	}
	if f.From != nil {
		clauses = append(clauses, fmt.Sprintf("created_at >= $%d", next))
		args = append(args, *f.From)
		next++
	}
	if f.To != nil {
		clauses = append(clauses, fmt.Sprintf("created_at <= $%d", next))
		args = append(args, *f.To)
		next++ //nolint:ineffassign
	}

	if len(clauses) == 0 {
		return "", nil
	}
	return " AND " + strings.Join(clauses, " AND "), args
}

// List returns domain events matching the filter, cursor-paginated.
func (r *DomainEventRepo) List(ctx context.Context, filter domain.DomainEventFilter, cursor core.Cursor, limit int) ([]domain.DomainEvent, bool, error) {
	where := "1=1"
	var args []any

	filterClause, filterArgs := buildDomainEventFilterClause(filter, 1)
	args = append(args, filterArgs...)
	where += filterClause

	if !cursor.IsZero() {
		where += fmt.Sprintf(" AND (created_at, id) < ($%d, $%d)", len(args)+1, len(args)+2)
		args = append(args, cursor.CreatedAt, cursor.ID)
	}

	args = append(args, limit+1)
	query := `SELECT ` + domainEventSelectColumns + ` FROM domain_events WHERE ` + where +
		fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT $%d`, len(args))

	rows, err := conn(ctx, r.pool).Query(ctx, query, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	out := make([]domain.DomainEvent, 0, limit+1)
	for rows.Next() {
		e, err := scanDomainEvent(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, e)
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
