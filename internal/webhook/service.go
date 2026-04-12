package webhook

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

type Service struct {
	txManager domain.TxManager
	webhooks  domain.WebhookRepository
}

func NewService(txManager domain.TxManager, webhooks domain.WebhookRepository) *Service {
	return &Service{
		txManager: txManager,
		webhooks:  webhooks,
	}
}

type CreateEndpointRequest struct {
	URL    string           `json:"url" validate:"required,url"`
	Events []core.EventType `json:"events"`
}

func (s *Service) CreateEndpoint(ctx context.Context, accountID core.AccountID, req CreateEndpointRequest) (*domain.WebhookEndpoint, error) {
	var ep *domain.WebhookEndpoint

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
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

func (s *Service) ListEndpoints(ctx context.Context, accountID core.AccountID, limit, offset int) ([]domain.WebhookEndpoint, int, error) {
	var endpoints []domain.WebhookEndpoint
	var total int

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		var err error
		endpoints, total, err = s.webhooks.ListEndpoints(ctx, limit, offset)
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return endpoints, total, nil
}

func (s *Service) DeleteEndpoint(ctx context.Context, accountID core.AccountID, endpointID core.WebhookEndpointID) error {
	return s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		return s.webhooks.DeleteEndpoint(ctx, endpointID)
	})
}

// Dispatch retrieves active endpoints for the event and delivers to each
// in a background goroutine. Fire-and-forget — delivery errors are logged.
func (s *Service) Dispatch(ctx context.Context, accountID core.AccountID, eventType core.EventType, payload json.RawMessage) {
	var endpoints []domain.WebhookEndpoint

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		var err error
		endpoints, err = s.webhooks.GetActiveEndpointsByEvent(ctx, eventType)
		return err
	})
	if err != nil {
		slog.Error("webhook dispatch: failed to fetch endpoints", "event", eventType, "error", err)
		return
	}

	for _, ep := range endpoints {
		event := &domain.WebhookEvent{
			ID:         core.NewWebhookEventID(),
			AccountID:  accountID,
			EndpointID: ep.ID,
			EventType:  eventType,
			Payload:    payload,
			Status:     core.DeliveryStatusPending,
			Attempts:   0,
			CreatedAt:  time.Now().UTC(),
		}
		if err := s.webhooks.CreateEvent(ctx, event); err != nil {
			slog.Error("webhook: failed to persist event", "endpoint", ep.URL, "event", eventType, "error", err)
			continue
		}

		go func() {
			s.deliver(context.Background(), event, ep, payload)
		}()
	}
}
