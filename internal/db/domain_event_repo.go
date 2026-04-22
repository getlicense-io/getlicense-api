package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/getlicense-io/getlicense-api/internal/core"
	sqlcgen "github.com/getlicense-io/getlicense-api/internal/db/sqlc/gen"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// domainEventColumns lists the 16 columns in the same order as the
// shared sqlcgen.DomainEvent struct. Kept for the integration test's
// ListSince seed INSERT; production path uses sqlc-generated queries.
const domainEventColumns = `id, account_id, environment, event_type, resource_type, resource_id, acting_account_id, identity_id, actor_label, actor_kind, api_key_id, grant_id, request_id, ip_address, payload, created_at`

// DomainEventRepo implements domain.DomainEventRepository using sqlc-generated queries.
type DomainEventRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.DomainEventRepository = (*DomainEventRepo)(nil)

// NewDomainEventRepo creates a new DomainEventRepo.
func NewDomainEventRepo(pool *pgxpool.Pool) *DomainEventRepo {
	return &DomainEventRepo{pool: pool, q: sqlcgen.New()}
}

// ipAddrPtrToStringPtr converts a pgx *netip.Addr (nullable inet) to
// the domain's *string representation. Invalid addrs become nil.
// Postgres-side inet for a single-host address may round-trip without
// the /32 suffix when stored as INET (not CIDR) — callers tolerate both.
func ipAddrPtrToStringPtr(a *netip.Addr) *string {
	if a == nil || !a.IsValid() {
		return nil
	}
	s := a.String()
	return &s
}

// stringPtrToIPAddrPtr parses the domain's *string IPAddress into a
// *netip.Addr for sqlc params. Returns (nil, nil) for a nil input and
// an error for an unparsable address — the service layer should have
// already validated format, so a parse failure here is a bug, not
// user-facing input.
func stringPtrToIPAddrPtr(s *string) (*netip.Addr, error) {
	if s == nil {
		return nil, nil
	}
	addr, err := netip.ParseAddr(*s)
	if err != nil {
		return nil, fmt.Errorf("domain_event: parse ip_address %q: %w", *s, err)
	}
	return &addr, nil
}

// domainEventFromRow is the translation seam between sqlcgen.DomainEvent
// and domain.DomainEvent. Empty payload ([] or "") is coerced to {} to
// preserve the hand-written repo's contract that callers always get
// valid JSON.
func domainEventFromRow(row sqlcgen.DomainEvent) domain.DomainEvent {
	payload := json.RawMessage(row.Payload)
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	return domain.DomainEvent{
		ID:              idFromPgUUID[core.DomainEventID](row.ID),
		AccountID:       idFromPgUUID[core.AccountID](row.AccountID),
		Environment:     core.Environment(row.Environment),
		EventType:       core.EventType(row.EventType),
		ResourceType:    row.ResourceType,
		ResourceID:      row.ResourceID,
		ActingAccountID: nullableIDFromPgUUID[core.AccountID](row.ActingAccountID),
		IdentityID:      nullableIDFromPgUUID[core.IdentityID](row.IdentityID),
		ActorLabel:      row.ActorLabel,
		ActorKind:       core.ActorKind(row.ActorKind),
		APIKeyID:        nullableIDFromPgUUID[core.APIKeyID](row.ApiKeyID),
		GrantID:         nullableIDFromPgUUID[core.GrantID](row.GrantID),
		RequestID:       row.RequestID,
		IPAddress:       ipAddrPtrToStringPtr(row.IpAddress),
		Payload:         payload,
		CreatedAt:       row.CreatedAt,
	}
}

// Create inserts a new domain event. Nil payload is coerced to {}.
func (r *DomainEventRepo) Create(ctx context.Context, e *domain.DomainEvent) error {
	if e.Payload == nil {
		e.Payload = json.RawMessage(`{}`)
	}
	ipAddr, err := stringPtrToIPAddrPtr(e.IPAddress)
	if err != nil {
		return err
	}
	return r.q.CreateDomainEvent(ctx, conn(ctx, r.pool), sqlcgen.CreateDomainEventParams{
		ID:              pgUUIDFromID(e.ID),
		AccountID:       pgUUIDFromID(e.AccountID),
		Environment:     string(e.Environment),
		EventType:       string(e.EventType),
		ResourceType:    e.ResourceType,
		ResourceID:      e.ResourceID,
		ActingAccountID: pgUUIDFromIDPtr(e.ActingAccountID),
		IdentityID:      pgUUIDFromIDPtr(e.IdentityID),
		ActorLabel:      e.ActorLabel,
		ActorKind:       string(e.ActorKind),
		ApiKeyID:        pgUUIDFromIDPtr(e.APIKeyID),
		GrantID:         pgUUIDFromIDPtr(e.GrantID),
		RequestID:       e.RequestID,
		IpAddress:       ipAddr,
		Payload:         e.Payload,
		CreatedAt:       e.CreatedAt,
	})
}

// Get returns the domain event with the given ID, or (nil, nil) on miss.
func (r *DomainEventRepo) Get(ctx context.Context, id core.DomainEventID) (*domain.DomainEvent, error) {
	row, err := r.q.GetDomainEventByID(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e := domainEventFromRow(row)
	return &e, nil
}

// List returns domain events matching the filter, cursor-paginated.
// 7 optional filters + keyset cursor on (created_at DESC, id DESC).
// Empty string filters and nil pointer filters are treated as "no filter".
func (r *DomainEventRepo) List(ctx context.Context, filter domain.DomainEventFilter, cursor core.Cursor, limit int) ([]domain.DomainEvent, bool, error) {
	ts, id := cursorParams(cursor)
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}
	var identityID, grantID pgtype.UUID
	if filter.IdentityID != nil {
		identityID = pgtype.UUID{Bytes: [16]byte(*filter.IdentityID), Valid: true}
	}
	if filter.GrantID != nil {
		grantID = pgtype.UUID{Bytes: [16]byte(*filter.GrantID), Valid: true}
	}

	rows, err := r.q.ListDomainEvents(ctx, conn(ctx, r.pool), sqlcgen.ListDomainEventsParams{
		ResourceType: nilIfEmpty(filter.ResourceType),
		ResourceID:   nilIfEmpty(filter.ResourceID),
		EventType:    nilIfEmpty(string(filter.EventType)),
		IdentityID:   identityID,
		GrantID:      grantID,
		FromTs:       filter.From,
		ToTs:         filter.To,
		CursorTs:     ts,
		CursorID:     cursorID,
		LimitPlusOne: int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.DomainEvent, 0, len(rows))
	for _, row := range rows {
		out = append(out, domainEventFromRow(row))
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}

// ListSince returns up to `limit` domain events with id > afterID,
// ordered by id ASC. Designed for the background webhook-fanout
// consumer — runs without RLS context, reading events across all
// tenants. Passes r.pool directly instead of conn(ctx, r.pool) to
// guarantee no tx (and no app.current_account_id) is used even if
// the caller happens to hold one in ctx.
func (r *DomainEventRepo) ListSince(ctx context.Context, afterID core.DomainEventID, limit int) ([]domain.DomainEvent, error) {
	rows, err := r.q.ListDomainEventsSince(ctx, r.pool, sqlcgen.ListDomainEventsSinceParams{
		ID:    pgUUIDFromID(afterID),
		Limit: int32(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.DomainEvent, 0, len(rows))
	for _, row := range rows {
		out = append(out, domainEventFromRow(row))
	}
	return out, nil
}
