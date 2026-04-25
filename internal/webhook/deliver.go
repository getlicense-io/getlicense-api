package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

const (
	deliveryTimeout    = 10 * time.Second
	maxResponseBodyLen = 2048 // 2 KiB
)

// newWebhookClient builds an http.Client that refuses to dial any
// private / loopback / link-local / cloud-metadata address once DNS
// has resolved the target host. This is the F-004 fix: the
// registration-time validator can only inspect IP literals in the
// URL, so a hostname that resolves to 169.254.169.254 (DNS rebinding)
// used to slip past. The dialer Control callback fires per-resolved-IP
// during Happy Eyeballs and rejects the connection before the TCP
// handshake, so the rebound target never receives the signed payload.
//
// CheckRedirect re-runs ValidateWebhookURL on every redirect target
// so a public endpoint that 302s to http://10.0.0.1/ is caught at
// the second dial, not sent the payload on the third.
//
// In development (isDev=true) both layers are relaxed so local
// e2e scenarios can deliver webhooks to localhost.
func newWebhookClient(isDev bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	// Control runs after DNS resolution and before the TCP handshake.
	// The address arg is host:port with host set to the resolved IP
	// string, so parsing it gives us the concrete peer we are about
	// to connect to. If DNS returns multiple records (Happy Eyeballs)
	// the Control callback is called once per record.
	if !isDev {
		dialer.Control = func(_ /*network*/ string, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("webhook: invalid dial address %q: %w", address, err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				// Should never happen — at dial time host is always
				// a literal IP. Refuse defensively.
				return fmt.Errorf("webhook: dial host is not an IP literal: %s", host)
			}
			if isBlockedIP(ip) {
				return fmt.Errorf("webhook: refusing to dial blocked address %s", ip)
			}
			return nil
		}
	}

	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        10,
	}

	return &http.Client{
		Timeout:   deliveryTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("webhook: too many redirects")
			}
			// Re-validate each redirect target. The dial-time guard
			// runs after this, but this rejects the hostname check
			// earlier and keeps the error message meaningful.
			return ValidateWebhookURL(req.URL.String(), isDev)
		},
	}
}

type webhookEnvelope struct {
	ID        string          `json:"id"`
	EventType core.EventType  `json:"event_type"`
	Data      json.RawMessage `json:"data"`
	Timestamp string          `json:"timestamp"`
}

// deliveryResult holds response details captured from a single POST attempt.
type deliveryResult struct {
	StatusCode      int
	ResponseBody    *string
	BodyTruncated   bool
	ResponseHeaders json.RawMessage
}

// AttemptDelivery performs ONE signed webhook POST attempt against
// the endpoint URL. Pure HTTP — no DB writes, no retry loop, no
// goroutines. The worker pool (internal/webhook/worker.go) calls
// this once per claimed row and decides what to record (delivered
// vs retry vs final) based on the return value.
//
// Returns a populated deliveryResult either way. postErr is nil on
// 2xx, non-nil on transport error or non-2xx response — same contract
// the old `deliver` retry loop treated as "failure, schedule retry".
//
// Exposed (capitalized) so background.go can pass it as the deliverFunc
// when constructing the worker pool. Marshalling and signing happen
// here so the worker stays oblivious to the wire format.
func (s *Service) AttemptDelivery(ctx context.Context, event *domain.WebhookEvent, endpoint domain.WebhookEndpoint) (deliveryResult, error) {
	eventID := event.ID.String()

	body, err := json.Marshal(webhookEnvelope{
		ID:        eventID,
		EventType: event.EventType,
		Data:      event.Payload,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		// Marshal failure is unrecoverable — surface it as a non-retryable
		// error. The worker treats every error the same; the retry budget
		// will exhaust and the row will land in `failed`.
		return deliveryResult{}, fmt.Errorf("webhook: marshal envelope: %w", err)
	}

	secret, err := s.masterKey.Decrypt(endpoint.SigningSecretEncrypted)
	if err != nil {
		// Decrypt failure means the ciphertext is corrupted, the master
		// key rotated without re-encrypting, or the bytes were never
		// populated (shouldn't happen post-startup-backfill). Surface as
		// non-2xx so the worker schedules a retry — the operator can
		// rotate the secret to recover.
		return deliveryResult{}, fmt.Errorf("webhook: decrypt signing secret: %w", err)
	}
	sig := crypto.HMACSHA256Sign(secret, body)
	return doPost(ctx, s.httpClient, endpoint.URL, eventID, sig, body)
}

// deliverOnce sends a single webhook POST attempt (no retries) and
// persists the result via the legacy UpdateEventStatus path. Used by
// Redeliver so the HTTP call is bounded and synchronous in the
// caller's request context. Worker-pool deliveries use AttemptDelivery
// + Mark{Delivered,FailedFinal} instead.
func (s *Service) deliverOnce(ctx context.Context, event *domain.WebhookEvent, endpoint domain.WebhookEndpoint, data json.RawMessage) {
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

	secret, err := s.masterKey.Decrypt(endpoint.SigningSecretEncrypted)
	if err != nil {
		slog.Error("webhook: failed to decrypt signing secret", "event_id", eventID, "error", err)
		return
	}
	sig := crypto.HMACSHA256Sign(secret, body)
	result, postErr := doPost(ctx, s.httpClient, endpoint.URL, eventID, sig, body)

	if postErr == nil {
		if err := s.webhooks.UpdateEventStatus(ctx, event.ID, core.DeliveryStatusDelivered, 1, &result.StatusCode, result.ResponseBody, result.BodyTruncated, result.ResponseHeaders, nil); err != nil {
			slog.Error("webhook: failed to update event status", "event_id", eventID, "error", err)
		}
		return
	}

	var respStatus *int
	if result.StatusCode != 0 {
		respStatus = &result.StatusCode
	}
	if err := s.webhooks.UpdateEventStatus(ctx, event.ID, core.DeliveryStatusFailed, 1, respStatus, result.ResponseBody, result.BodyTruncated, result.ResponseHeaders, nil); err != nil {
		slog.Error("webhook: failed to update event status", "event_id", eventID, "error", err)
	}
}

// doPost sends a single webhook POST request. Returns delivery result details
// and any error. StatusCode is 0 when no HTTP response was received.
func doPost(ctx context.Context, client *http.Client, url, eventID, sig string, body []byte) (deliveryResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return deliveryResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GetLicense-Signature", sig)
	req.Header.Set("X-GetLicense-Event-Id", eventID)

	resp, err := client.Do(req)
	if err != nil {
		return deliveryResult{}, err
	}

	// Read response body up to maxResponseBodyLen + 1 to detect truncation.
	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyLen+1))
	// Drain any remaining body to allow connection reuse.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()

	var result deliveryResult
	result.StatusCode = resp.StatusCode

	if readErr == nil && len(respBody) > 0 {
		if len(respBody) > maxResponseBodyLen {
			truncated := string(respBody[:maxResponseBodyLen])
			result.ResponseBody = &truncated
			result.BodyTruncated = true
		} else {
			s := string(respBody)
			result.ResponseBody = &s
		}
	}

	// Capture response headers as JSON.
	if len(resp.Header) > 0 {
		headerMap := make(map[string]string, len(resp.Header))
		for k := range resp.Header {
			headerMap[k] = resp.Header.Get(k)
		}
		if hj, err := json.Marshal(headerMap); err == nil {
			result.ResponseHeaders = json.RawMessage(hj)
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, fmt.Errorf("webhook: non-2xx response: %d", resp.StatusCode)
	}
	return result, nil
}
