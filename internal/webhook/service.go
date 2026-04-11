package webhook

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Service handles webhook endpoint management and event dispatching.
type Service struct {
	txManager domain.TxManager
	webhooks  domain.WebhookRepository
}

// NewService constructs a new webhook Service.
func NewService(txManager domain.TxManager, webhooks domain.WebhookRepository) *Service {
	return &Service{
		txManager: txManager,
		webhooks:  webhooks,
	}
}

// CreateEndpointRequest holds the fields needed to register a new webhook endpoint.
type CreateEndpointRequest struct {
	URL    string   `json:"url" validate:"required,url"`
	Events []string `json:"events"`
}

// CreateEndpoint registers a new webhook endpoint for the given account.
// A random 32-byte signing secret is generated and stored (hex-encoded).
func (s *Service) CreateEndpoint(ctx context.Context, accountID core.AccountID, req CreateEndpointRequest) (*domain.WebhookEndpoint, error) {
	var ep *domain.WebhookEndpoint

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		var secretBytes [32]byte
		if _, err := rand.Read(secretBytes[:]); err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to generate signing secret")
		}
		signingSecret := hex.EncodeToString(secretBytes[:])

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

// ListEndpoints returns a paginated list of webhook endpoints for the given account.
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

// DeleteEndpoint removes a webhook endpoint by ID within the given account.
func (s *Service) DeleteEndpoint(ctx context.Context, accountID core.AccountID, endpointID core.WebhookEndpointID) error {
	return s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		return s.webhooks.DeleteEndpoint(ctx, endpointID)
	})
}

// Dispatch retrieves all active endpoints subscribed to eventType and fires
// DeliverWebhook for each in a separate goroutine. It is fire-and-forget:
// the caller is not blocked and delivery errors are not propagated.
func (s *Service) Dispatch(ctx context.Context, accountID core.AccountID, eventType core.EventType, payload json.RawMessage) {
	var endpoints []domain.WebhookEndpoint

	err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
		var err error
		endpoints, err = s.webhooks.GetActiveEndpointsByEvent(ctx, eventType)
		return err
	})
	if err != nil {
		// Best-effort: if we can't fetch endpoints, there's nothing to dispatch.
		return
	}

	for _, ep := range endpoints {
		ep := ep // capture loop variable
		go func() {
			// Use a fresh background context so delivery isn't cancelled when
			// the caller's request context ends.
			_ = DeliverWebhook(context.Background(), ep, eventType, payload)
		}()
	}
}
