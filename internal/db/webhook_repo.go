package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	sqlcgen "github.com/getlicense-io/getlicense-api/internal/db/sqlc/gen"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WebhookRepo implements domain.WebhookRepository using sqlc-generated queries.
type WebhookRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.WebhookRepository = (*WebhookRepo)(nil)

// NewWebhookRepo creates a new WebhookRepo.
func NewWebhookRepo(pool *pgxpool.Pool) *WebhookRepo {
	return &WebhookRepo{pool: pool, q: sqlcgen.New()}
}

// webhookEndpointFromRow is the translation seam between sqlcgen.WebhookEndpoint
// and domain.WebhookEndpoint. Events text[] → []core.EventType via per-element cast.
func webhookEndpointFromRow(row sqlcgen.WebhookEndpoint) domain.WebhookEndpoint {
	events := make([]core.EventType, len(row.Events))
	for i, e := range row.Events {
		events[i] = core.EventType(e)
	}
	return domain.WebhookEndpoint{
		ID:            idFromPgUUID[core.WebhookEndpointID](row.ID),
		AccountID:     idFromPgUUID[core.AccountID](row.AccountID),
		URL:           row.Url,
		Events:        events,
		SigningSecret: row.SigningSecret,
		Active:        row.Active,
		Environment:   core.Environment(row.Environment),
		CreatedAt:     row.CreatedAt,
	}
}

// webhookEventFromRow is the translation seam between sqlcgen.WebhookEvent
// and domain.WebhookEvent. Payload/ResponseHeaders []byte → json.RawMessage
// via bare cast (matches machine_repo.go Metadata pattern).
func webhookEventFromRow(row sqlcgen.WebhookEvent) domain.WebhookEvent {
	return domain.WebhookEvent{
		ID:                    idFromPgUUID[core.WebhookEventID](row.ID),
		AccountID:             idFromPgUUID[core.AccountID](row.AccountID),
		EndpointID:            idFromPgUUID[core.WebhookEndpointID](row.EndpointID),
		EventType:             core.EventType(row.EventType),
		Payload:               json.RawMessage(row.Payload),
		Status:                core.DeliveryStatus(row.Status),
		Attempts:              int(row.Attempts),
		LastAttemptedAt:       row.LastAttemptedAt,
		ResponseStatus:        int32PtrToIntPtr(row.ResponseStatus),
		DomainEventID:         nullableIDFromPgUUID[core.DomainEventID](row.DomainEventID),
		ResponseBody:          row.ResponseBody,
		ResponseBodyTruncated: row.ResponseBodyTruncated,
		ResponseHeaders:       json.RawMessage(row.ResponseHeaders),
		NextRetryAt:           row.NextRetryAt,
		Environment:           core.Environment(row.Environment),
		CreatedAt:             row.CreatedAt,
	}
}

// CreateEndpoint inserts a new webhook endpoint.
func (r *WebhookRepo) CreateEndpoint(ctx context.Context, ep *domain.WebhookEndpoint) error {
	events := make([]string, len(ep.Events))
	for i, e := range ep.Events {
		events[i] = string(e)
	}
	return r.q.CreateWebhookEndpoint(ctx, conn(ctx, r.pool), sqlcgen.CreateWebhookEndpointParams{
		ID:            pgUUIDFromID(ep.ID),
		AccountID:     pgUUIDFromID(ep.AccountID),
		Url:           ep.URL,
		Events:        events,
		SigningSecret: ep.SigningSecret,
		Active:        ep.Active,
		CreatedAt:     ep.CreatedAt,
		Environment:   string(ep.Environment),
	})
}

// GetEndpointByID returns the webhook endpoint with the given ID, or (nil, nil) on miss.
func (r *WebhookRepo) GetEndpointByID(ctx context.Context, id core.WebhookEndpointID) (*domain.WebhookEndpoint, error) {
	row, err := r.q.GetWebhookEndpointByID(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ep := webhookEndpointFromRow(row)
	return &ep, nil
}

// ListEndpoints returns one cursor page of webhook endpoints, ordered
// (created_at DESC, id DESC) with id-tiebreaker. limit+1 probe detects has_more.
func (r *WebhookRepo) ListEndpoints(ctx context.Context, cursor core.Cursor, limit int) ([]domain.WebhookEndpoint, bool, error) {
	ts, id := cursorParams(cursor)
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}
	rows, err := r.q.ListWebhookEndpoints(ctx, conn(ctx, r.pool), sqlcgen.ListWebhookEndpointsParams{
		CursorTs:     ts,
		CursorID:     cursorID,
		LimitPlusOne: int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.WebhookEndpoint, 0, len(rows))
	for _, row := range rows {
		out = append(out, webhookEndpointFromRow(row))
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}

// DeleteEndpoint removes the webhook endpoint with the given ID.
// Returns ErrWebhookEndpointNotFound if no row matched.
func (r *WebhookRepo) DeleteEndpoint(ctx context.Context, id core.WebhookEndpointID) error {
	n, err := r.q.DeleteWebhookEndpoint(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if err != nil {
		return err
	}
	if n == 0 {
		return core.NewAppError(core.ErrWebhookEndpointNotFound, "Webhook endpoint not found")
	}
	return nil
}

// GetActiveEndpointsByEvent returns all active endpoints subscribed to
// the given event type. An endpoint with an empty events array subscribes
// to every event.
func (r *WebhookRepo) GetActiveEndpointsByEvent(ctx context.Context, eventType core.EventType) ([]domain.WebhookEndpoint, error) {
	rows, err := r.q.GetActiveWebhookEndpointsByEvent(ctx, conn(ctx, r.pool), string(eventType))
	if err != nil {
		return nil, err
	}
	out := make([]domain.WebhookEndpoint, 0, len(rows))
	for _, row := range rows {
		out = append(out, webhookEndpointFromRow(row))
	}
	return out, nil
}

// CreateEvent inserts a new webhook event delivery record.
func (r *WebhookRepo) CreateEvent(ctx context.Context, event *domain.WebhookEvent) error {
	return r.q.CreateWebhookEvent(ctx, conn(ctx, r.pool), sqlcgen.CreateWebhookEventParams{
		ID:                    pgUUIDFromID(event.ID),
		AccountID:             pgUUIDFromID(event.AccountID),
		EndpointID:            pgUUIDFromID(event.EndpointID),
		EventType:             string(event.EventType),
		Payload:               event.Payload,
		Status:                string(event.Status),
		Attempts:              int32(event.Attempts),
		LastAttemptedAt:       event.LastAttemptedAt,
		ResponseStatus:        intPtrToInt32Ptr(event.ResponseStatus),
		CreatedAt:             event.CreatedAt,
		Environment:           string(event.Environment),
		DomainEventID:         pgUUIDFromIDPtr(event.DomainEventID),
		ResponseBody:          event.ResponseBody,
		ResponseBodyTruncated: event.ResponseBodyTruncated,
		ResponseHeaders:       event.ResponseHeaders,
		NextRetryAt:           event.NextRetryAt,
	})
}

// UpdateEventStatus updates the delivery status, attempts count, response
// details, and next retry time. last_attempted_at is set to NOW() by SQL.
func (r *WebhookRepo) UpdateEventStatus(ctx context.Context, id core.WebhookEventID, status core.DeliveryStatus, attempts int, responseStatus *int, responseBody *string, responseBodyTruncated bool, responseHeaders json.RawMessage, nextRetryAt *time.Time) error {
	return r.q.UpdateWebhookEventStatus(ctx, conn(ctx, r.pool), sqlcgen.UpdateWebhookEventStatusParams{
		ID:                    pgUUIDFromID(id),
		Status:                string(status),
		Attempts:              int32(attempts),
		ResponseStatus:        intPtrToInt32Ptr(responseStatus),
		ResponseBody:          responseBody,
		ResponseBodyTruncated: responseBodyTruncated,
		ResponseHeaders:       responseHeaders,
		NextRetryAt:           nextRetryAt,
	})
}

// GetEventByID returns the webhook event with the given ID, or (nil, nil) on miss.
func (r *WebhookRepo) GetEventByID(ctx context.Context, id core.WebhookEventID) (*domain.WebhookEvent, error) {
	row, err := r.q.GetWebhookEventByID(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ev := webhookEventFromRow(row)
	return &ev, nil
}

// ListEventsByEndpoint returns one cursor page of webhook events for the
// given endpoint with optional (event_type, status) filters. NULL-guarded
// filters via sqlc.narg — empty string ⇒ no filter.
func (r *WebhookRepo) ListEventsByEndpoint(ctx context.Context, endpointID core.WebhookEndpointID, filter domain.WebhookDeliveryFilter, cursor core.Cursor, limit int) ([]domain.WebhookEvent, bool, error) {
	ts, id := cursorParams(cursor)
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}
	rows, err := r.q.ListWebhookEventsByEndpoint(ctx, conn(ctx, r.pool), sqlcgen.ListWebhookEventsByEndpointParams{
		EndpointID:   pgUUIDFromID(endpointID),
		EventType:    nilIfEmpty(string(filter.EventType)),
		Status:       nilIfEmpty(string(filter.Status)),
		CursorTs:     ts,
		CursorID:     cursorID,
		LimitPlusOne: int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.WebhookEvent, 0, len(rows))
	for _, row := range rows {
		out = append(out, webhookEventFromRow(row))
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}
