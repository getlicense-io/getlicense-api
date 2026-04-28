package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
// `id` is the STABLE event identifier — equals `domain_event_id` for
// every delivery. Two duplicate fanouts of the same domain event (the
// at-least-once tail of a checkpoint-then-crash window) carry the
// same `id`, so consumers MUST dedupe by it. `delivery_id` is the
// per-attempt `webhook_event.id` — different on every attempt, useful
// for debugging a specific delivery.
type webhookEnvelope struct {
	ID         string          `json:"id"`
	DeliveryID string          `json:"delivery_id"`
	EventType  core.EventType  `json:"event_type"`
	Data       json.RawMessage `json:"data"`
	Timestamp  string          `json:"timestamp"`
}

// buildEnvelope is the single source of truth for envelope id
// derivation. AttemptDelivery uses it so the payload shape stays
// uniform between worker-pool and admin redeliver paths.
func buildEnvelope(event *domain.WebhookEvent, data json.RawMessage, ts time.Time) webhookEnvelope {
	return webhookEnvelope{
		ID:         event.DomainEventID.String(),
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

	// AAD-bound ciphertexts. Supplying the wrong endpoint id here
	// means GCM auth fails and we surface as non-2xx so the worker
	// schedules a retry.
	aad := crypto.WebhookSigningSecretAAD(endpoint.ID)
	secret, err := s.masterKey.Decrypt(endpoint.SigningSecretEncrypted, aad)
	if err != nil {
		// Decrypt failure means the ciphertext is corrupted or the
		// master key rotated without re-encrypting. Surface as non-2xx
		// so the worker schedules a retry — the operator can rotate
		// the secret to recover.
		return deliveryResult{}, fmt.Errorf("webhook: decrypt signing secret: %w", err)
	}

	// Signature includes a timestamp claim so a leaked signed payload
	// cannot be replayed past the receiver's skew tolerance (recommend
	// ≤ 300s). Scheme version is encoded as a `v1=` prefix on the
	// value so a future upgrade can introduce `v2=` alongside.
	tsUnix := now.Unix()
	sig := "v1=" + crypto.HMACSHA256Sign(secret, []byte(strconv.FormatInt(tsUnix, 10)+"."+string(body)))

	return doPost(ctx, s.httpClient, endpoint.URL, envelope.DeliveryID, sig, tsUnix, body)
}

// doPost sends a single webhook POST request. Returns delivery result details
// and any error. StatusCode is 0 when no HTTP response was received.
//
// Headers emitted:
//   - X-GetLicense-Timestamp    unix seconds at signing time
//   - X-GetLicense-Signature    "v1=" + hex(hmac(secret, ts.body))
//   - X-GetLicense-Delivery-Id  per-attempt webhook_event.id
//
// The stable event id (envelope.id, equal to domain_event_id) lives
// in the JSON body so receivers can dedupe at-least-once deliveries
// without a dedicated header. Delivery-Id is unique per attempt and
// useful for debugging a specific HTTP call.
//
// Verification recipe:
//  1. Read X-GetLicense-Timestamp; reject if |now - ts| > 300 seconds.
//  2. signed_payload = ts + "." + raw_body
//  3. expected = "v1=" + hmac_sha256_hex(signing_secret, signed_payload)
//  4. Constant-time compare expected to X-GetLicense-Signature.
func doPost(ctx context.Context, client *http.Client, url, deliveryID, sig string, ts int64, body []byte) (deliveryResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return deliveryResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GetLicense-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-GetLicense-Signature", sig)
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
