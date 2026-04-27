package webhook

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

type Service struct {
	txManager    domain.TxManager
	webhooks     domain.WebhookRepository
	domainEvents domain.DomainEventRepository
	masterKey    *crypto.MasterKey // encrypts/decrypts signing secrets
	isDev        bool
	httpClient   *http.Client // SSRF-safe: resolved IPs re-checked at dial time. F-004.
}

func NewService(txManager domain.TxManager, webhooks domain.WebhookRepository, domainEvents domain.DomainEventRepository, masterKey *crypto.MasterKey, isDev bool) *Service {
	return &Service{
		txManager:    txManager,
		webhooks:     webhooks,
		domainEvents: domainEvents,
		masterKey:    masterKey,
		isDev:        isDev,
		httpClient:   newWebhookClient(isDev),
	}
}

type CreateEndpointRequest struct {
	URL    string           `json:"url" validate:"required,url"`
	Events []core.EventType `json:"events"`
}

// CreateEndpointResult is the response shape for CreateEndpoint.
//
// SigningSecret is the raw HMAC key the customer's webhook receiver
// uses to verify inbound payload signatures. Returned ONCE here and
// never retrievable again — the value is only ever stored encrypted
// at rest (PR-3.2). Customers MUST capture it from this response.
// To replace a lost or compromised secret, call
// POST /v1/webhooks/:id/rotate-signing-secret, which mints a fresh
// secret and returns it once with the same shape.
type CreateEndpointResult struct {
	Endpoint      *domain.WebhookEndpoint `json:"endpoint"`
	SigningSecret string                  `json:"signing_secret"`
}

// RotateSigningSecretResult is the response shape for the rotation
// endpoint. Same one-shot exposure semantics as CreateEndpointResult.
type RotateSigningSecretResult struct {
	Endpoint                *domain.WebhookEndpoint `json:"endpoint"`
	SigningSecret           string                  `json:"signing_secret"`
	PreviousSecretExpiresAt time.Time               `json:"previous_secret_expires_at"`
}

const signingSecretRotationGrace = 10 * time.Minute

func (s *Service) CreateEndpoint(ctx context.Context, accountID core.AccountID, env core.Environment, req CreateEndpointRequest) (*CreateEndpointResult, error) {
	// Validate URL before persisting.
	if err := ValidateWebhookURL(req.URL, s.isDev); err != nil {
		return nil, core.NewAppError(core.ErrValidationError, err.Error())
	}

	var (
		ep        *domain.WebhookEndpoint
		plaintext string
	)

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		secret, err := crypto.GenerateRandomHex(32)
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to generate signing secret")
		}

		// Bind ciphertext to (endpoint, signing_secret) via AAD so an
		// attacker with DB write access cannot swap this row's
		// signing_secret_encrypted with another encrypted column —
		// GCM auth fails on the wrong AAD. PR-C.
		endpointID := core.NewWebhookEndpointID()
		aad := crypto.WebhookSigningSecretAAD(endpointID)
		encrypted, err := s.masterKey.Encrypt([]byte(secret), aad)
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to encrypt signing secret")
		}

		// Normalize nil to empty slice so the response serializes
		// `events: []` (matching the OpenAPI schema), not `events: null`.
		// An empty events array means "subscribe to all event types"
		// (see ListActiveEndpointsForEvent).
		events := req.Events
		if events == nil {
			events = []core.EventType{}
		}

		endpoint := &domain.WebhookEndpoint{
			ID:                     endpointID,
			AccountID:              accountID,
			URL:                    req.URL,
			Events:                 events,
			SigningSecretEncrypted: encrypted,
			Active:                 true,
			Environment:            env,
			CreatedAt:              time.Now().UTC(),
		}
		if err := s.webhooks.CreateEndpoint(ctx, endpoint); err != nil {
			return err
		}

		ep = endpoint
		plaintext = secret
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &CreateEndpointResult{Endpoint: ep, SigningSecret: plaintext}, nil
}

// RotateSigningSecret generates a fresh current signing secret and
// keeps the old current secret in the previous slot for a short
// verification grace window. Deliveries sign only with the current
// secret; receivers can verify against current or previous until
// PreviousSecretExpiresAt, then call FinishSigningSecretRotation or
// let the expired previous secret be ignored.
func (s *Service) RotateSigningSecret(ctx context.Context, accountID core.AccountID, env core.Environment, endpointID core.WebhookEndpointID) (*RotateSigningSecretResult, error) {
	secret, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to generate signing secret")
	}
	aad := crypto.WebhookSigningSecretAAD(endpointID)
	encrypted, err := s.masterKey.Encrypt([]byte(secret), aad)
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to encrypt signing secret")
	}

	var ep *domain.WebhookEndpoint
	previousExpiresAt := time.Now().UTC().Add(signingSecretRotationGrace)
	err = s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		existing, gerr := s.webhooks.GetEndpointByID(ctx, endpointID)
		if gerr != nil {
			return gerr
		}
		if existing == nil {
			return core.NewAppError(core.ErrWebhookEndpointNotFound, "Webhook endpoint not found")
		}
		if rerr := s.webhooks.RotateSigningSecret(ctx, endpointID, encrypted, existing.SigningSecretEncrypted, previousExpiresAt); rerr != nil {
			return rerr
		}
		existing.PreviousSigningSecretEncrypted = existing.SigningSecretEncrypted
		existing.PreviousSigningSecretExpiresAt = &previousExpiresAt
		existing.SigningSecretEncrypted = encrypted
		ep = existing
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &RotateSigningSecretResult{Endpoint: ep, SigningSecret: secret, PreviousSecretExpiresAt: previousExpiresAt}, nil
}

func (s *Service) FinishSigningSecretRotation(ctx context.Context, accountID core.AccountID, env core.Environment, endpointID core.WebhookEndpointID) (*domain.WebhookEndpoint, error) {
	var ep *domain.WebhookEndpoint
	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		existing, gerr := s.webhooks.GetEndpointByID(ctx, endpointID)
		if gerr != nil {
			return gerr
		}
		if existing == nil {
			return core.NewAppError(core.ErrWebhookEndpointNotFound, "Webhook endpoint not found")
		}
		if rerr := s.webhooks.FinishSigningSecretRotation(ctx, endpointID); rerr != nil {
			return rerr
		}
		existing.PreviousSigningSecretEncrypted = nil
		existing.PreviousSigningSecretExpiresAt = nil
		ep = existing
		return nil
	})
	return ep, err
}

func (s *Service) ListEndpoints(ctx context.Context, accountID core.AccountID, env core.Environment, cursor core.Cursor, limit int) ([]domain.WebhookEndpoint, bool, error) {
	var endpoints []domain.WebhookEndpoint
	var hasMore bool

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		var err error
		endpoints, hasMore, err = s.webhooks.ListEndpoints(ctx, cursor, limit)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return endpoints, hasMore, nil
}

func (s *Service) DeleteEndpoint(ctx context.Context, accountID core.AccountID, env core.Environment, endpointID core.WebhookEndpointID) error {
	return s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		return s.webhooks.DeleteEndpoint(ctx, endpointID)
	})
}

// ListDeliveries returns webhook event deliveries for an endpoint, cursor-paginated.
func (s *Service) ListDeliveries(ctx context.Context, accountID core.AccountID, env core.Environment, endpointID core.WebhookEndpointID, filter domain.WebhookDeliveryFilter, cursor core.Cursor, limit int) ([]domain.WebhookEvent, bool, error) {
	var events []domain.WebhookEvent
	var hasMore bool

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		// Verify endpoint exists and belongs to this account.
		ep, err := s.webhooks.GetEndpointByID(ctx, endpointID)
		if err != nil {
			return err
		}
		if ep == nil {
			return core.NewAppError(core.ErrWebhookEndpointNotFound, "Webhook endpoint not found")
		}

		events, hasMore, err = s.webhooks.ListEventsByEndpoint(ctx, endpointID, filter, cursor, limit)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return events, hasMore, nil
}

// GetDelivery returns a single webhook event delivery by ID.
func (s *Service) GetDelivery(ctx context.Context, accountID core.AccountID, env core.Environment, endpointID core.WebhookEndpointID, eventID core.WebhookEventID) (*domain.WebhookEvent, error) {
	var event *domain.WebhookEvent

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		// Verify endpoint exists and belongs to this account.
		ep, err := s.webhooks.GetEndpointByID(ctx, endpointID)
		if err != nil {
			return err
		}
		if ep == nil {
			return core.NewAppError(core.ErrWebhookEndpointNotFound, "Webhook endpoint not found")
		}

		ev, err := s.webhooks.GetEventByID(ctx, eventID)
		if err != nil {
			return err
		}
		if ev == nil || ev.EndpointID != endpointID {
			return core.NewAppError(core.ErrWebhookEventNotFound, "Webhook delivery not found")
		}

		event = ev
		return nil
	})
	if err != nil {
		return nil, err
	}
	return event, nil
}

// Redeliver re-dispatches the domain event linked to a webhook delivery.
// It creates a new webhook_event row and delivers synchronously.
func (s *Service) Redeliver(ctx context.Context, accountID core.AccountID, env core.Environment, endpointID core.WebhookEndpointID, eventID core.WebhookEventID) (*domain.WebhookEvent, error) {
	var newEvent *domain.WebhookEvent

	// Load the original delivery and endpoint inside an RLS tx.
	var originalEvent *domain.WebhookEvent
	var endpoint *domain.WebhookEndpoint

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		ep, err := s.webhooks.GetEndpointByID(ctx, endpointID)
		if err != nil {
			return err
		}
		if ep == nil {
			return core.NewAppError(core.ErrWebhookEndpointNotFound, "Webhook endpoint not found")
		}
		endpoint = ep

		ev, err := s.webhooks.GetEventByID(ctx, eventID)
		if err != nil {
			return err
		}
		if ev == nil || ev.EndpointID != endpointID {
			return core.NewAppError(core.ErrWebhookEventNotFound, "Webhook delivery not found")
		}
		originalEvent = ev
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Load the domain event. The row lives in the same tenant as the
	// originating delivery, so wrap in WithTargetAccount — PR-B
	// (migration 034) made the RLS bypass explicit, and bare-pool
	// reads on domain_events fail closed.
	var domainEvent *domain.DomainEvent
	if err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		ev, gerr := s.domainEvents.Get(ctx, originalEvent.DomainEventID)
		if gerr != nil {
			return gerr
		}
		domainEvent = ev
		return nil
	}); err != nil {
		return nil, err
	}
	if domainEvent == nil {
		return nil, core.NewAppError(core.ErrEventNotFound, "Linked domain event not found")
	}

	// Create a new delivery row.
	newEv := &domain.WebhookEvent{
		ID:            core.NewWebhookEventID(),
		AccountID:     originalEvent.AccountID,
		EndpointID:    endpointID,
		EventType:     originalEvent.EventType,
		Payload:       domainEvent.Payload,
		Status:        core.DeliveryStatusPending,
		Attempts:      0,
		DomainEventID: originalEvent.DomainEventID,
		Environment:   originalEvent.Environment,
		CreatedAt:     time.Now().UTC(),
	}

	// Persist the new event row under RLS.
	err = s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		return s.webhooks.CreateEvent(ctx, newEv)
	})
	if err != nil {
		return nil, err
	}

	// Deliver synchronously with a single attempt (no retries).
	s.deliverOnce(context.Background(), newEv, *endpoint, domainEvent.Payload)

	// Re-read the event to get updated status after delivery.
	err = s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		ev, err := s.webhooks.GetEventByID(ctx, newEv.ID)
		if err != nil {
			return err
		}
		if ev != nil {
			newEvent = ev
		} else {
			newEvent = newEv
		}
		return nil
	})
	if err != nil {
		// If re-read fails, return the pre-delivery event.
		newEvent = newEv
	}

	return newEvent, nil
}

// DeliverDomainEvents fans out a batch of domain events into the
// webhook_events outbox. Each (event, endpoint) pair becomes one
// pending row.
//
// Actual HTTP delivery is performed by the worker pool consuming
// the outbox — see internal/webhook/worker.go. This method NEVER
// spawns goroutines, never sleeps, and never blocks on the network.
//
// Idempotency model (best-effort, NOT enforced by a unique index):
// rows are inserted as the dispatcher checkpoint advances. The
// checkpoint is bumped after each successful batch, so on a clean
// shutdown duplicate enqueue is rare. Worst case is at-least-once
// delivery — the industry contract for webhooks. Consumers MUST
// dedupe by `envelope.id`, which equals the stable
// `domain_event_id` from PR-A.1. (An earlier draft of migration 032
// added a unique partial index on (domain_event_id, endpoint_id)
// for absorption, but it was dropped because it conflicted with the
// admin redeliver path and with mid-retry rows; see migration 032
// header for details.)
//
// Returns the ID of the last domain event that was FULLY enqueued
// (endpoint lookup succeeded AND every per-endpoint CreateEvent
// succeeded inside a single tx). The caller advances the dispatcher
// checkpoint to this ID — events beyond it are reprocessed on the
// next tick.
//
// If event N's enqueue fails, returns the last event before N. If
// no events succeeded, returns the zero ID — the caller leaves the
// checkpoint unchanged.
//
// All-or-nothing per event: every endpoint's row goes in one tx, so
// a partial enqueue is impossible. Working endpoints don't see
// duplicates from a retry; the failing endpoint gets re-attempted
// on the next tick.
func (s *Service) DeliverDomainEvents(ctx context.Context, events []domain.DomainEvent) core.DomainEventID {
	var lastSucceeded core.DomainEventID
	for _, event := range events {
		var endpoints []domain.WebhookEndpoint
		err := s.txManager.WithTargetAccount(ctx, event.AccountID, event.Environment, func(ctx context.Context) error {
			var err error
			endpoints, err = s.webhooks.GetActiveEndpointsByEvent(ctx, event.EventType)
			return err
		})
		if err != nil {
			slog.Error("webhook delivery: failed to list endpoints; halting batch advance",
				"error", err, "event_id", event.ID)
			return lastSucceeded
		}
		if len(endpoints) == 0 {
			// No subscribers — event is "fully enqueued" by vacuous
			// truth. Advance past it.
			lastSucceeded = event.ID
			continue
		}

		err = s.txManager.WithTargetAccount(ctx, event.AccountID, event.Environment, func(ctx context.Context) error {
			for _, ep := range endpoints {
				we := &domain.WebhookEvent{
					ID:            core.NewWebhookEventID(),
					AccountID:     event.AccountID,
					EndpointID:    ep.ID,
					EventType:     event.EventType,
					Payload:       event.Payload,
					Status:        core.DeliveryStatusPending,
					Attempts:      0,
					DomainEventID: event.ID,
					Environment:   event.Environment,
					CreatedAt:     time.Now().UTC(),
				}
				if err := s.webhooks.CreateEvent(ctx, we); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			slog.Error("webhook delivery: failed to enqueue event atomically; halting batch advance",
				"error", err, "event_id", event.ID, "endpoints", len(endpoints))
			return lastSucceeded
		}
		lastSucceeded = event.ID
	}
	return lastSucceeded
}
