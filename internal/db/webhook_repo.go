package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// scanWebhookEndpoint scans a webhook endpoint row from a scannable (pgx.Row or pgx.Rows).
func scanWebhookEndpoint(s scannable) (domain.WebhookEndpoint, error) {
	var ep domain.WebhookEndpoint
	var rawID, rawAccountID uuid.UUID
	var rawEvents []string
	var envStr string
	err := s.Scan(
		&rawID, &rawAccountID,
		&ep.URL, &rawEvents, &ep.SigningSecret, &ep.Active,
		&envStr, &ep.CreatedAt,
	)
	if err != nil {
		return ep, err
	}
	ep.ID = core.WebhookEndpointID(rawID)
	ep.AccountID = core.AccountID(rawAccountID)
	ep.Events = make([]core.EventType, len(rawEvents))
	for i, e := range rawEvents {
		ep.Events[i] = core.EventType(e)
	}
	ep.Environment = core.Environment(envStr)
	return ep, nil
}

const webhookEndpointColumns = `id, account_id, url, events, signing_secret, active, environment, created_at`

const webhookEventColumns = `id, account_id, endpoint_id, event_type, payload, status, attempts, last_attempted_at, response_status, domain_event_id, response_body, response_body_truncated, response_headers, next_retry_at, created_at, environment`

// scanWebhookEvent scans a webhook event row from a scannable.
func scanWebhookEvent(s scannable) (domain.WebhookEvent, error) {
	var ev domain.WebhookEvent
	var rawID, rawAccountID, rawEndpointID uuid.UUID
	var rawDomainEventID *uuid.UUID
	var eventType, status, envStr string
	var payload, responseHeaders []byte

	err := s.Scan(
		&rawID, &rawAccountID, &rawEndpointID,
		&eventType, &payload, &status,
		&ev.Attempts, &ev.LastAttemptedAt, &ev.ResponseStatus,
		&rawDomainEventID, &ev.ResponseBody, &ev.ResponseBodyTruncated,
		&responseHeaders, &ev.NextRetryAt,
		&ev.CreatedAt, &envStr,
	)
	if err != nil {
		return ev, err
	}

	ev.ID = core.WebhookEventID(rawID)
	ev.AccountID = core.AccountID(rawAccountID)
	ev.EndpointID = core.WebhookEndpointID(rawEndpointID)
	ev.EventType = core.EventType(eventType)
	ev.Status = core.DeliveryStatus(status)
	ev.Environment = core.Environment(envStr)

	if rawDomainEventID != nil {
		did := core.DomainEventID(*rawDomainEventID)
		ev.DomainEventID = &did
	}

	if len(payload) > 0 {
		ev.Payload = json.RawMessage(payload)
	}
	if len(responseHeaders) > 0 {
		ev.ResponseHeaders = json.RawMessage(responseHeaders)
	}

	return ev, nil
}

// WebhookRepo implements domain.WebhookRepository using PostgreSQL.
type WebhookRepo struct {
	pool *pgxpool.Pool
}

var _ domain.WebhookRepository = (*WebhookRepo)(nil)

// NewWebhookRepo creates a new WebhookRepo.
func NewWebhookRepo(pool *pgxpool.Pool) *WebhookRepo {
	return &WebhookRepo{pool: pool}
}

// CreateEndpoint inserts a new webhook endpoint into the database.
func (r *WebhookRepo) CreateEndpoint(ctx context.Context, ep *domain.WebhookEndpoint) error {
	q := conn(ctx, r.pool)
	events := make([]string, len(ep.Events))
	for i, e := range ep.Events {
		events[i] = string(e)
	}
	_, err := q.Exec(ctx,
		`INSERT INTO webhook_endpoints (`+webhookEndpointColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		uuid.UUID(ep.ID), uuid.UUID(ep.AccountID),
		ep.URL, events, ep.SigningSecret, ep.Active,
		string(ep.Environment), ep.CreatedAt,
	)
	return err
}

// GetEndpointByID returns the webhook endpoint with the given ID, or (nil, nil) on miss.
func (r *WebhookRepo) GetEndpointByID(ctx context.Context, id core.WebhookEndpointID) (*domain.WebhookEndpoint, error) {
	q := conn(ctx, r.pool)
	ep, err := scanWebhookEndpoint(q.QueryRow(ctx,
		`SELECT `+webhookEndpointColumns+` FROM webhook_endpoints WHERE id = $1`,
		uuid.UUID(id),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &ep, nil
}

func (r *WebhookRepo) ListEndpoints(ctx context.Context, cursor core.Cursor, limit int) ([]domain.WebhookEndpoint, bool, error) {
	q := conn(ctx, r.pool)

	var rows pgx.Rows
	var err error
	if cursor.IsZero() {
		rows, err = q.Query(ctx,
			`SELECT `+webhookEndpointColumns+` FROM webhook_endpoints
			 ORDER BY created_at DESC, id DESC LIMIT $1`,
			limit+1,
		)
	} else {
		rows, err = q.Query(ctx,
			`SELECT `+webhookEndpointColumns+` FROM webhook_endpoints
			 WHERE (created_at, id) < ($1, $2)
			 ORDER BY created_at DESC, id DESC LIMIT $3`,
			cursor.CreatedAt, cursor.ID, limit+1,
		)
	}
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	out := make([]domain.WebhookEndpoint, 0, limit+1)
	for rows.Next() {
		ep, err := scanWebhookEndpoint(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, ep)
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

// DeleteEndpoint removes the webhook endpoint with the given ID.
// Returns an error if the webhook endpoint does not exist.
func (r *WebhookRepo) DeleteEndpoint(ctx context.Context, id core.WebhookEndpointID) error {
	q := conn(ctx, r.pool)
	tag, err := q.Exec(ctx, `DELETE FROM webhook_endpoints WHERE id = $1`, uuid.UUID(id))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.NewAppError(core.ErrWebhookEndpointNotFound, "Webhook endpoint not found")
	}
	return nil
}

// GetActiveEndpointsByEvent returns all active endpoints subscribed to the given event type.
// An endpoint with an empty events array receives all events.
func (r *WebhookRepo) GetActiveEndpointsByEvent(ctx context.Context, eventType core.EventType) ([]domain.WebhookEndpoint, error) {
	q := conn(ctx, r.pool)
	rows, err := q.Query(ctx,
		`SELECT `+webhookEndpointColumns+`
		 FROM webhook_endpoints
		 WHERE active = true AND ($1 = ANY(events) OR events = '{}')`,
		string(eventType),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	endpoints := make([]domain.WebhookEndpoint, 0)
	for rows.Next() {
		ep, err := scanWebhookEndpoint(rows)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, ep)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return endpoints, nil
}

// CreateEvent inserts a new webhook event delivery record into the database.
func (r *WebhookRepo) CreateEvent(ctx context.Context, event *domain.WebhookEvent) error {
	q := conn(ctx, r.pool)

	var rawDomainEventID *uuid.UUID
	if event.DomainEventID != nil {
		u := uuid.UUID(*event.DomainEventID)
		rawDomainEventID = &u
	}

	_, err := q.Exec(ctx,
		`INSERT INTO webhook_events (`+webhookEventColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		uuid.UUID(event.ID), uuid.UUID(event.AccountID), uuid.UUID(event.EndpointID),
		string(event.EventType), event.Payload,
		string(event.Status), event.Attempts, event.LastAttemptedAt,
		event.ResponseStatus, rawDomainEventID,
		event.ResponseBody, event.ResponseBodyTruncated,
		event.ResponseHeaders, event.NextRetryAt,
		event.CreatedAt, string(event.Environment),
	)
	return err
}

// UpdateEventStatus updates the delivery status, attempts count, response details, and next retry time.
func (r *WebhookRepo) UpdateEventStatus(ctx context.Context, id core.WebhookEventID, status core.DeliveryStatus, attempts int, responseStatus *int, responseBody *string, responseBodyTruncated bool, responseHeaders json.RawMessage, nextRetryAt *time.Time) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`UPDATE webhook_events
		 SET status = $2, attempts = $3, response_status = $4, last_attempted_at = NOW(),
		     response_body = $5, response_body_truncated = $6, response_headers = $7, next_retry_at = $8
		 WHERE id = $1`,
		uuid.UUID(id), string(status), attempts, responseStatus,
		responseBody, responseBodyTruncated, responseHeaders, nextRetryAt,
	)
	return err
}

// GetEventByID returns the webhook event with the given ID, or (nil, nil) on miss.
func (r *WebhookRepo) GetEventByID(ctx context.Context, id core.WebhookEventID) (*domain.WebhookEvent, error) {
	q := conn(ctx, r.pool)
	ev, err := scanWebhookEvent(q.QueryRow(ctx,
		`SELECT `+webhookEventColumns+` FROM webhook_events WHERE id = $1`,
		uuid.UUID(id),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &ev, nil
}

// ListEventsByEndpoint returns webhook events for an endpoint, cursor-paginated with optional filters.
func (r *WebhookRepo) ListEventsByEndpoint(ctx context.Context, endpointID core.WebhookEndpointID, filter domain.WebhookDeliveryFilter, cursor core.Cursor, limit int) ([]domain.WebhookEvent, bool, error) {
	q := conn(ctx, r.pool)

	where := "endpoint_id = $1"
	args := []any{uuid.UUID(endpointID)}

	if filter.EventType != "" {
		args = append(args, string(filter.EventType))
		where += fmt.Sprintf(" AND event_type = $%d", len(args))
	}
	if filter.Status != "" {
		args = append(args, string(filter.Status))
		where += fmt.Sprintf(" AND status = $%d", len(args))
	}

	if !cursor.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		where += fmt.Sprintf(" AND (created_at, id) < ($%d, $%d)", len(args)-1, len(args))
	}

	args = append(args, limit+1)
	query := `SELECT ` + webhookEventColumns + ` FROM webhook_events WHERE ` + where +
		fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT $%d`, len(args))

	rows, err := q.Query(ctx, query, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	out := make([]domain.WebhookEvent, 0, limit+1)
	for rows.Next() {
		ev, err := scanWebhookEvent(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, ev)
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
