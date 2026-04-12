package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

var retryDelays = [...]time.Duration{
	1 * time.Second,
	5 * time.Second,
	30 * time.Second,
	5 * time.Minute,
	30 * time.Minute,
}

const deliveryTimeout = 10 * time.Second

// Shared client for connection reuse across deliveries.
var httpClient = &http.Client{Timeout: deliveryTimeout}

type webhookEnvelope struct {
	ID        string          `json:"id"`
	EventType core.EventType  `json:"event_type"`
	Data      json.RawMessage `json:"data"`
	Timestamp string          `json:"timestamp"`
}

// deliver sends a signed webhook POST to the endpoint URL, persisting delivery
// status after each attempt. Retries up to len(retryDelays) times on failure.
func (s *Service) deliver(ctx context.Context, event *domain.WebhookEvent, endpoint domain.WebhookEndpoint, data json.RawMessage) {
	eventID := event.ID.String()

	body, err := json.Marshal(webhookEnvelope{
		ID:        eventID,
		EventType: event.EventType,
		Data:      data,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		slog.Error("webhook: failed to marshal envelope", "event_id", eventID, "error", err)
		return
	}

	sig := crypto.HMACSHA256Sign([]byte(endpoint.SigningSecret), body)

	totalAttempts := len(retryDelays) + 1
	var lastStatusCode int

	for attempt := range totalAttempts {
		statusCode, postErr := doPost(ctx, endpoint.URL, eventID, sig, body)
		lastStatusCode = statusCode

		if postErr == nil {
			// Delivery succeeded.
			if err := s.webhooks.UpdateEventStatus(ctx, event.ID, core.DeliveryStatusDelivered, attempt+1, &statusCode); err != nil {
				slog.Error("webhook: failed to update event status", "event_id", eventID, "error", err)
			}
			return
		}

		// Build response status pointer: nil when no HTTP response was received.
		var respStatus *int
		if statusCode != 0 {
			respStatus = &statusCode
		}

		if attempt >= len(retryDelays) {
			// All retries exhausted.
			if err := s.webhooks.UpdateEventStatus(ctx, event.ID, core.DeliveryStatusFailed, attempt+1, respStatus); err != nil {
				slog.Error("webhook: failed to update event status", "event_id", eventID, "error", err)
			}
			slog.Error("webhook: delivery failed after all attempts",
				"event_id", eventID, "endpoint", endpoint.URL, "attempts", totalAttempts, "error", postErr)
			return
		}

		// Failed but more retries remain — update status as pending.
		if err := s.webhooks.UpdateEventStatus(ctx, event.ID, core.DeliveryStatusPending, attempt+1, respStatus); err != nil {
			slog.Error("webhook: failed to update event status", "event_id", eventID, "error", err)
		}

		select {
		case <-ctx.Done():
			// Context cancelled — mark as failed with last known status.
			var finalStatus *int
			if lastStatusCode != 0 {
				finalStatus = &lastStatusCode
			}
			if err := s.webhooks.UpdateEventStatus(ctx, event.ID, core.DeliveryStatusFailed, attempt+1, finalStatus); err != nil {
				slog.Error("webhook: failed to update event status on cancellation", "event_id", eventID, "error", err)
			}
			return
		case <-time.After(retryDelays[attempt]):
		}
	}
}

// doPost sends a single webhook POST request. Returns the HTTP status code and
// any error. Status code is 0 when no HTTP response was received.
func doPost(ctx context.Context, url, eventID, sig string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GetLicense-Signature", sig)
	req.Header.Set("X-GetLicense-Event-Id", eventID)

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	// Drain body to allow connection reuse, capped at 1MB.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("webhook: non-2xx response: %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}
