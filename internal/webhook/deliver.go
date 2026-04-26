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
	"strconv"
	"syscall"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

const (
	deliveryTimeout    = 10 * time.Second
	maxResponseBodyLen = 2048 // 2 KiB

	// PR-A.1 (item 8): cap response-header surface area so a malicious
	// or misbehaving customer endpoint can't bloat response_headers
	// jsonb. The wire-level cap (MaxResponseHeaderBytes on the transport)
	// short-circuits at the network read; the per-header caps below
	// bound what we PERSIST after a successful read.
	maxHeaderKeyLen            = 256
	maxHeaderValueLen          = 1024
	maxStoredHeaderCount       = 32
	maxResponseHeaderWireBytes = 16 * 1024
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
		// PR-A.1 (item 8): cap response-header bytes at the wire so a
		// pathological endpoint cannot stream a multi-MB header block
		// and force us to allocate (and persist) it.
		MaxResponseHeaderBytes: maxResponseHeaderWireBytes,
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

// webhookEnvelope is the JSON wire shape of every outbound delivery.
//
// PR-A.1 (item 1): `id` is the STABLE event identifier — equals
// `domain_event_id` for every delivery sourced from the durable event
// log. Two duplicate fanouts of the same domain event (the at-least-
// once tail of a checkpoint-then-crash window) carry the same `id`,
// so consumers MUST dedupe by it. `delivery_id` is the per-attempt
// `webhook_event.id` — different on every attempt, useful for
// debugging a specific delivery.
//
// Fallback: redelivers issued via POST /v1/webhooks/.../redeliver
// also have a non-nil DomainEventID, so they reuse the stable id of
// the originating event (which is correct — operator-initiated retry
// of the SAME event). For legacy rows that predate the domain event
// log (DomainEventID == nil, blocked at the redeliver path with
// delivery_predates_event_log) the builder falls back to
// webhook_event.id so the field is never empty on the wire.
type webhookEnvelope struct {
	ID         string          `json:"id"`
	DeliveryID string          `json:"delivery_id"`
	EventType  core.EventType  `json:"event_type"`
	Data       json.RawMessage `json:"data"`
	Timestamp  string          `json:"timestamp"`
}

// buildEnvelope is the single source of truth for envelope id
// derivation. AttemptDelivery and deliverOnce both use it so the
// id-fallback rule never drifts between worker-pool and admin
// redeliver paths.
func buildEnvelope(event *domain.WebhookEvent, data json.RawMessage, ts time.Time) webhookEnvelope {
	publicID := event.ID.String()
	if event.DomainEventID != nil {
		publicID = event.DomainEventID.String()
	}
	return webhookEnvelope{
		ID:         publicID,
		DeliveryID: event.ID.String(),
		EventType:  event.EventType,
		Data:       data,
		Timestamp:  ts.UTC().Format(time.RFC3339),
	}
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
	now := time.Now().UTC()
	envelope := buildEnvelope(event, event.Payload, now)
	body, err := json.Marshal(envelope)
	if err != nil {
		// Marshal failure is unrecoverable — surface it as a non-retryable
		// error. The worker treats every error the same; the retry budget
		// will exhaust and the row will land in `failed`.
		return deliveryResult{}, fmt.Errorf("webhook: marshal envelope: %w", err)
	}

	// PR-C: DecryptAuto handles both v1 (legacy, no-AAD) and v2
	// (AAD-bound) envelopes transparently. AAD is mandatory for v2 —
	// supplying the wrong endpoint id here means the v2 path fails
	// auth and falls through to v1, where it would also fail because
	// the wrong endpoint's bytes are not a valid v1 envelope for this
	// row. Either way the call returns an error and we surface it as
	// non-2xx so the worker schedules a retry.
	aad := crypto.WebhookSigningSecretAAD(endpoint.ID)
	secret, err := s.masterKey.DecryptAuto(endpoint.SigningSecretEncrypted, aad)
	if err != nil {
		// Decrypt failure means the ciphertext is corrupted, the master
		// key rotated without re-encrypting, or the bytes were never
		// populated (shouldn't happen post-startup-backfill). Surface as
		// non-2xx so the worker schedules a retry — the operator can
		// rotate the secret to recover.
		return deliveryResult{}, fmt.Errorf("webhook: decrypt signing secret: %w", err)
	}
	sigV1 := crypto.HMACSHA256Sign(secret, body)

	// PR-A.1 (item 9): v2 signature includes a timestamp claim so a
	// leaked signed payload cannot be replayed past the receiver's
	// skew tolerance (recommend ≤ 300s). Scheme version is encoded
	// as a `v1=` prefix on the value so a future upgrade can introduce
	// `v2=` alongside without breaking dual-emit verifiers.
	tsUnix := now.Unix()
	sigV2Raw := crypto.HMACSHA256Sign(secret, []byte(strconv.FormatInt(tsUnix, 10)+"."+string(body)))
	sigV2 := "v1=" + sigV2Raw

	return doPost(ctx, s.httpClient, endpoint.URL, envelope.ID, envelope.DeliveryID, sigV1, sigV2, tsUnix, body)
}

// deliverOnce sends a single webhook POST attempt (no retries) and
// persists the result via the legacy UpdateEventStatus path. Used by
// Redeliver so the HTTP call is bounded and synchronous in the
// caller's request context. Worker-pool deliveries use AttemptDelivery
// + Mark{Delivered,FailedFinal} instead.
func (s *Service) deliverOnce(ctx context.Context, event *domain.WebhookEvent, endpoint domain.WebhookEndpoint, data json.RawMessage) {
	now := time.Now().UTC()
	envelope := buildEnvelope(event, data, now)
	body, err := json.Marshal(envelope)
	if err != nil {
		slog.Error("webhook: failed to marshal envelope", "event_id", event.ID, "error", err)
		return
	}

	// Same AAD-aware path as AttemptDelivery. PR-C.
	aad := crypto.WebhookSigningSecretAAD(endpoint.ID)
	secret, err := s.masterKey.DecryptAuto(endpoint.SigningSecretEncrypted, aad)
	if err != nil {
		slog.Error("webhook: failed to decrypt signing secret", "event_id", event.ID, "error", err)
		return
	}
	sigV1 := crypto.HMACSHA256Sign(secret, body)
	tsUnix := now.Unix()
	sigV2Raw := crypto.HMACSHA256Sign(secret, []byte(strconv.FormatInt(tsUnix, 10)+"."+string(body)))
	sigV2 := "v1=" + sigV2Raw
	result, postErr := doPost(ctx, s.httpClient, endpoint.URL, envelope.ID, envelope.DeliveryID, sigV1, sigV2, tsUnix, body)

	if postErr == nil {
		if err := s.webhooks.UpdateEventStatus(ctx, event.ID, core.DeliveryStatusDelivered, 1, &result.StatusCode, result.ResponseBody, result.BodyTruncated, result.ResponseHeaders, nil); err != nil {
			slog.Error("webhook: failed to update event status", "event_id", event.ID, "error", err)
		}
		return
	}

	var respStatus *int
	if result.StatusCode != 0 {
		respStatus = &result.StatusCode
	}
	if err := s.webhooks.UpdateEventStatus(ctx, event.ID, core.DeliveryStatusFailed, 1, respStatus, result.ResponseBody, result.BodyTruncated, result.ResponseHeaders, nil); err != nil {
		slog.Error("webhook: failed to update event status", "event_id", event.ID, "error", err)
	}
}

// doPost sends a single webhook POST request. Returns delivery result details
// and any error. StatusCode is 0 when no HTTP response was received.
//
// Headers emitted (PR-A.1 item 9 dual-emit scheme):
//   - X-GetLicense-Signature        v1, hex(hmac(secret, body))           [legacy, kept for back-compat]
//   - X-GetLicense-Event-Id         stable event id (envelope.id)         [legacy, kept for back-compat]
//   - X-GetLicense-Timestamp        unix seconds at signing time          [v2, new]
//   - X-GetLicense-Signature-V2     "v1=" + hex(hmac(secret, ts.body))    [v2, new]
//   - X-GetLicense-Delivery-Id      per-attempt webhook_event.id          [v2, new]
//
// Verification recipe for receivers (v2):
//  1. Read X-GetLicense-Timestamp; reject if |now - ts| > 300 seconds.
//  2. signed_payload = ts + "." + raw_body
//  3. expected = "v1=" + hmac_sha256_hex(signing_secret, signed_payload)
//  4. Constant-time compare expected to X-GetLicense-Signature-V2.
//  5. Optional dedup: store (X-GetLicense-Event-Id, X-GetLicense-Delivery-Id)
//     for at-least-once handling (Event-Id is stable per logical event;
//     Delivery-Id is unique per attempt).
func doPost(ctx context.Context, client *http.Client, url, eventID, deliveryID, sigV1, sigV2 string, ts int64, body []byte) (deliveryResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return deliveryResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Legacy v1 headers — kept for backward compat with existing
	// consumers built against the body-only signature scheme.
	req.Header.Set("X-GetLicense-Signature", sigV1)
	req.Header.Set("X-GetLicense-Event-Id", eventID)
	// v2 headers — anti-replay via timestamp; verify with timestamp.body.
	req.Header.Set("X-GetLicense-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-GetLicense-Signature-V2", sigV2)
	req.Header.Set("X-GetLicense-Delivery-Id", deliveryID)

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

	// Capture response headers as JSON, with PR-A.1 (item 8) caps on
	// per-key length, per-value length, and total stored count. The
	// transport's MaxResponseHeaderBytes already capped the wire read;
	// these caps bound what we persist into response_headers jsonb.
	if len(resp.Header) > 0 {
		mapCap := len(resp.Header)
		if mapCap > maxStoredHeaderCount {
			mapCap = maxStoredHeaderCount
		}
		headerMap := make(map[string]string, mapCap)
		for k := range resp.Header {
			if len(headerMap) >= maxStoredHeaderCount {
				break
			}
			key := k
			if len(key) > maxHeaderKeyLen {
				key = key[:maxHeaderKeyLen]
			}
			val := resp.Header.Get(k)
			if len(val) > maxHeaderValueLen {
				val = val[:maxHeaderValueLen]
			}
			headerMap[key] = val
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
