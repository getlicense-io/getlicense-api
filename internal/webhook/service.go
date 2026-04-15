package webhook

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

type Service struct {
	txManager  domain.TxManager
	webhooks   domain.WebhookRepository
	isDev      bool
	httpClient *http.Client // SSRF-safe: resolved IPs re-checked at dial time. F-004.
}

func NewService(txManager domain.TxManager, webhooks domain.WebhookRepository, isDev bool) *Service {
	return &Service{
		txManager:  txManager,
		webhooks:   webhooks,
		isDev:      isDev,
		httpClient: newWebhookClient(isDev),
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

// Dispatch retrieves active endpoints for the event and delivers to each
// in a background goroutine. Fire-and-forget — delivery errors are logged.
func (s *Service) Dispatch(ctx context.Context, accountID core.AccountID, env core.Environment, eventType core.EventType, payload json.RawMessage) {
	var endpoints []domain.WebhookEndpoint

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
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
			ID:          core.NewWebhookEventID(),
			AccountID:   accountID,
			EndpointID:  ep.ID,
			EventType:   eventType,
			Payload:     payload,
			Status:      core.DeliveryStatusPending,
			Attempts:    0,
			Environment: env,
			CreatedAt:   time.Now().UTC(),
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
