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
	isDev        bool
	httpClient   *http.Client // SSRF-safe: resolved IPs re-checked at dial time. F-004.
}

func NewService(txManager domain.TxManager, webhooks domain.WebhookRepository, domainEvents domain.DomainEventRepository, isDev bool) *Service {
	return &Service{
		txManager:    txManager,
		webhooks:     webhooks,
		domainEvents: domainEvents,
		isDev:        isDev,
		httpClient:   newWebhookClient(isDev),
	}
}

type CreateEndpointRequest struct {
	URL    string           `json:"url" validate:"required,url"`
	Events []core.EventType `json:"events"`
}

func (s *Service) CreateEndpoint(ctx context.Context, accountID core.AccountID, env core.Environment, req CreateEndpointRequest) (*domain.WebhookEndpoint, error) {
	// Validate URL before persisting.
	if err := ValidateWebhookURL(req.URL, s.isDev); err != nil {
		return nil, core.NewAppError(core.ErrValidationError, err.Error())
	}

	var ep *domain.WebhookEndpoint

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		signingSecret, err := crypto.GenerateRandomHex(32)
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to generate signing secret")
		}

		endpoint := &domain.WebhookEndpoint{
			ID:            core.NewWebhookEndpointID(),
			AccountID:     accountID,
			URL:           req.URL,
			Events:        req.Events,
			SigningSecret: signingSecret,
			Active:        true,
			Environment:   env,
			CreatedAt:     time.Now().UTC(),
		}
		if err := s.webhooks.CreateEndpoint(ctx, endpoint); err != nil {
			return err
		}

		ep = endpoint
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ep, nil
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

	// Check that the delivery has a linked domain event.
	if originalEvent.DomainEventID == nil {
		return nil, core.NewAppError(core.ErrDeliveryPredatesEventLog, "Delivery predates event log; cannot redeliver")
	}

	// Load the domain event (runs without RLS — domain events are global).
	domainEvent, err := s.domainEvents.Get(ctx, *originalEvent.DomainEventID)
	if err != nil {
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

// DeliverDomainEvents dispatches webhook deliveries for a batch of
// domain events read from the domain_events table. Each event is
// scoped to its own account+environment via WithTargetAccount so
// GetActiveEndpointsByEvent runs under the correct RLS context.
// Fire-and-forget — errors are logged, never returned.
func (s *Service) DeliverDomainEvents(ctx context.Context, events []domain.DomainEvent) {
	for _, event := range events {
		var endpoints []domain.WebhookEndpoint

		err := s.txManager.WithTargetAccount(ctx, event.AccountID, event.Environment, func(ctx context.Context) error {
			var err error
			endpoints, err = s.webhooks.GetActiveEndpointsByEvent(ctx, event.EventType)
			return err
		})
		if err != nil {
			slog.Error("webhook delivery: failed to list endpoints", "error", err, "event_id", event.ID)
			continue
		}

		for _, ep := range endpoints {
			domainEventID := event.ID
			we := &domain.WebhookEvent{
				ID:            core.NewWebhookEventID(),
				AccountID:     event.AccountID,
				EndpointID:    ep.ID,
				EventType:     event.EventType,
				Payload:       event.Payload,
				Status:        core.DeliveryStatusPending,
				Attempts:      0,
				DomainEventID: &domainEventID,
				Environment:   event.Environment,
				CreatedAt:     time.Now().UTC(),
			}
			if err := s.txManager.WithTargetAccount(ctx, event.AccountID, event.Environment, func(ctx context.Context) error {
				return s.webhooks.CreateEvent(ctx, we)
			}); err != nil {
				slog.Error("webhook: failed to persist event", "endpoint", ep.URL, "event_type", event.EventType, "error", err)
				continue
			}

			go func() {
				s.deliver(context.Background(), we, ep, event.Payload)
			}()
		}
	}
}
