package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

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

// DeliverWebhook sends a signed webhook POST to endpoint.URL.
// Retries up to len(retryDelays) times on failure.
func DeliverWebhook(ctx context.Context, endpoint domain.WebhookEndpoint, eventType core.EventType, data json.RawMessage) error {
	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("webhook: failed to generate event ID: %w", err)
	}
	eventID := id.String()

	body, err := json.Marshal(webhookEnvelope{
		ID:        eventID,
		EventType: eventType,
		Data:      data,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("webhook: failed to marshal envelope: %w", err)
	}

	sig := crypto.HMACSHA256Sign([]byte(endpoint.SigningSecret), body)

	var lastErr error
	for attempt := range len(retryDelays) + 1 {
		lastErr = doPost(ctx, endpoint.URL, eventID, sig, body)
		if lastErr == nil {
			return nil
		}

		if attempt >= len(retryDelays) {
			break
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retryDelays[attempt]):
		}
	}

	return fmt.Errorf("webhook: delivery failed after %d attempts: %w", len(retryDelays)+1, lastErr)
}

func doPost(ctx context.Context, url, eventID, sig string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GetLicense-Signature", sig)
	req.Header.Set("X-GetLicense-Event-Id", eventID)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	// Drain body to allow connection reuse, capped at 1MB.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: non-2xx response: %d", resp.StatusCode)
	}
	return nil
}
