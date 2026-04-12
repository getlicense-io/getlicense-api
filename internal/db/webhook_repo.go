package db

import (
	"context"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/google/uuid"
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

// ListEndpoints returns a paginated list of webhook endpoints and the total count.
func (r *WebhookRepo) ListEndpoints(ctx context.Context, limit, offset int) ([]domain.WebhookEndpoint, int, error) {
	q := conn(ctx, r.pool)

	var total int
	if err := q.QueryRow(ctx, `SELECT COUNT(*) FROM webhook_endpoints`).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := q.Query(ctx,
		`SELECT `+webhookEndpointColumns+` FROM webhook_endpoints ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	endpoints := make([]domain.WebhookEndpoint, 0, limit)
	for rows.Next() {
		ep, err := scanWebhookEndpoint(rows)
		if err != nil {
			return nil, 0, err
		}
		endpoints = append(endpoints, ep)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return endpoints, total, nil
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

	endpoints := make([]domain.WebhookEndpoint, 0, 0)
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
	_, err := q.Exec(ctx,
		`INSERT INTO webhook_events (id, account_id, endpoint_id, event_type, payload,
		 status, attempts, last_attempted_at, response_status, environment, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		uuid.UUID(event.ID), uuid.UUID(event.AccountID), uuid.UUID(event.EndpointID),
		string(event.EventType), event.Payload,
		string(event.Status), event.Attempts, event.LastAttemptedAt,
		event.ResponseStatus, string(event.Environment), event.CreatedAt,
	)
	return err
}

// UpdateEventStatus updates the delivery status, attempts count, and response status of a webhook event.
func (r *WebhookRepo) UpdateEventStatus(ctx context.Context, id core.WebhookEventID, status core.DeliveryStatus, attempts int, responseStatus *int) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`UPDATE webhook_events
		 SET status = $2, attempts = $3, response_status = $4, last_attempted_at = NOW()
		 WHERE id = $1`,
		uuid.UUID(id), string(status), attempts, responseStatus,
	)
	return err
}

