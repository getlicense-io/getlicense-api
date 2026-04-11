package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// RetryDelays defines the back-off intervals between successive delivery retries.
// The first attempt is made immediately; each entry here is the delay before
// the next retry.
var RetryDelays = []time.Duration{
	1 * time.Second,
	5 * time.Second,
	30 * time.Second,
	5 * time.Minute,
	30 * time.Minute,
}

// DeliveryTimeout is the per-attempt HTTP timeout.
const DeliveryTimeout = 10 * time.Second

// webhookEnvelope is the JSON body sent to the subscriber.
type webhookEnvelope struct {
	ID        string          `json:"id"`
	EventType string          `json:"event_type"`
	Data      json.RawMessage `json:"data"`
	Timestamp string          `json:"timestamp"`
}

// SignPayload computes the HMAC-SHA256 hex signature of payload using secret.
func SignPayload(secret string, payload []byte) string {
	return crypto.HMACSHA256Sign([]byte(secret), payload)
}

// DeliverWebhook sends a signed webhook POST to endpoint.URL for the given
// eventType and data. It retries up to len(RetryDelays) times on failure,
// sleeping according to RetryDelays between attempts.
// Returns nil on the first 2xx response; returns an error if all attempts fail.
func DeliverWebhook(ctx context.Context, endpoint domain.WebhookEndpoint, eventType core.EventType, data json.RawMessage) error {
	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("webhook: failed to generate event ID: %w", err)
	}
	eventID := id.String()

	envelope := webhookEnvelope{
		ID:        eventID,
		EventType: string(eventType),
		Data:      data,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("webhook: failed to marshal envelope: %w", err)
	}

	sig := SignPayload(endpoint.SigningSecret, body)

	client := &http.Client{Timeout: DeliveryTimeout}

	var lastErr error
	for attempt := 0; ; attempt++ {
		lastErr = doPost(ctx, client, endpoint.URL, eventID, sig, body)
		if lastErr == nil {
			return nil
		}

		if attempt >= len(RetryDelays) {
			break
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(RetryDelays[attempt]):
		}
	}

	return fmt.Errorf("webhook: delivery failed after %d attempts: %w", len(RetryDelays)+1, lastErr)
}

// doPost executes a single POST attempt.
func doPost(ctx context.Context, client *http.Client, url, eventID, sig string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GetLicense-Signature", sig)
	req.Header.Set("X-GetLicense-Event-Id", eventID)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: non-2xx response: %d", resp.StatusCode)
	}
	return nil
}
