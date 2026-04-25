package webhook

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

func TestHMACSigning_HexLength(t *testing.T) {
	sig := crypto.HMACSHA256Sign([]byte("test-secret"), []byte(`{"event":"test"}`))
	if len(sig) != 64 {
		t.Errorf("expected 64-char hex signature, got %d chars: %s", len(sig), sig)
	}
}

// TestRetrySchedule_Count guards the worker-pool retry budget. Six
// entries = six retries after the initial attempt = seven total
// attempts before MarkFailedFinal. Changing the schedule length
// changes durable production behavior — bump the count here only
// after deciding the new shape on purpose.
func TestRetrySchedule_Count(t *testing.T) {
	if len(retrySchedule) != 6 {
		t.Errorf("expected 6 retry schedule entries, got %d", len(retrySchedule))
	}
}

// TestBuildEnvelope_PrefersDomainEventID: the public envelope `id`
// MUST equal the stable domain_event_id when present so consumers
// can dedupe duplicate fanouts (PR-A.1 item 1). The webhook_event.id
// (per-attempt) lives on `delivery_id` instead.
func TestBuildEnvelope_PrefersDomainEventID(t *testing.T) {
	domainID := core.NewDomainEventID()
	ev := &domain.WebhookEvent{
		ID:            core.NewWebhookEventID(),
		DomainEventID: &domainID,
		EventType:     core.EventType("license.created"),
		Payload:       json.RawMessage(`{}`),
	}

	env := buildEnvelope(ev, ev.Payload, time.Now().UTC())

	if env.ID != domainID.String() {
		t.Errorf("envelope.id: want %s (domain_event_id), got %s", domainID, env.ID)
	}
	if env.DeliveryID != ev.ID.String() {
		t.Errorf("envelope.delivery_id: want %s (webhook_event.id), got %s", ev.ID, env.DeliveryID)
	}
}

// TestBuildEnvelope_FallsBackToWebhookEventID: legacy rows from
// before the domain event log have DomainEventID==nil. The builder
// MUST fall back to webhook_event.id so the wire field is never
// empty (consumers may still want SOME id for logging even if dedup
// is degraded).
func TestBuildEnvelope_FallsBackToWebhookEventID(t *testing.T) {
	ev := &domain.WebhookEvent{
		ID:            core.NewWebhookEventID(),
		DomainEventID: nil, // legacy / pre-event-log row
		EventType:     core.EventType("license.created"),
		Payload:       json.RawMessage(`{}`),
	}

	env := buildEnvelope(ev, ev.Payload, time.Now().UTC())

	if env.ID != ev.ID.String() {
		t.Errorf("envelope.id fallback: want %s (webhook_event.id), got %s", ev.ID, env.ID)
	}
	if env.DeliveryID != ev.ID.String() {
		t.Errorf("envelope.delivery_id: want %s (webhook_event.id), got %s", ev.ID, env.DeliveryID)
	}
}

// TestBuildEnvelope_DeliveryIDAlwaysWebhookEventID locks in the
// invariant that DeliveryID is ALWAYS the per-attempt webhook_event.id
// regardless of whether DomainEventID is set. Two redeliver attempts
// of the same logical event must produce different DeliveryIDs.
func TestBuildEnvelope_DeliveryIDAlwaysWebhookEventID(t *testing.T) {
	domainID := core.NewDomainEventID()
	ev1 := &domain.WebhookEvent{ID: core.NewWebhookEventID(), DomainEventID: &domainID, Payload: json.RawMessage(`{}`)}
	ev2 := &domain.WebhookEvent{ID: core.NewWebhookEventID(), DomainEventID: &domainID, Payload: json.RawMessage(`{}`)}

	env1 := buildEnvelope(ev1, ev1.Payload, time.Now().UTC())
	env2 := buildEnvelope(ev2, ev2.Payload, time.Now().UTC())

	if env1.ID != env2.ID {
		t.Errorf("redeliver envelopes must share id: got %s vs %s", env1.ID, env2.ID)
	}
	if env1.DeliveryID == env2.DeliveryID {
		t.Errorf("redeliver envelopes must have distinct delivery_id, both got %s", env1.DeliveryID)
	}
}

// TestDoPost_EmitsBothV1AndV2Signatures verifies the dual-emit
// signature scheme on the wire. v1 = hex(hmac(secret, body)) for
// back-compat; v2 = "v1=" + hex(hmac(secret, ts + "." + body)) for
// anti-replay. Both headers MUST be present; both signatures MUST
// verify against the supplied secret.
func TestDoPost_EmitsBothV1AndV2Signatures(t *testing.T) {
	secret := []byte("test-secret-for-signatures")
	body := []byte(`{"id":"abc","event_type":"license.created"}`)
	ts := time.Now().UTC().Unix()
	wantSigV1 := crypto.HMACSHA256Sign(secret, body)
	wantSigV2Raw := crypto.HMACSHA256Sign(secret, []byte(strconv.FormatInt(ts, 10)+"."+string(body)))
	wantSigV2 := "v1=" + wantSigV2Raw

	var gotHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	res, err := doPost(t.Context(), client, srv.URL, "stable-event-id", "per-attempt-delivery-id", wantSigV1, wantSigV2, ts, body)
	if err != nil {
		t.Fatalf("doPost returned error: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	// v1 (legacy) headers
	if got := gotHeaders.Get("X-Getlicense-Signature"); got != wantSigV1 {
		t.Errorf("X-GetLicense-Signature: want %s, got %s", wantSigV1, got)
	}
	if got := gotHeaders.Get("X-Getlicense-Event-Id"); got != "stable-event-id" {
		t.Errorf("X-GetLicense-Event-Id: want stable-event-id, got %s", got)
	}
	// v2 (new) headers
	if got := gotHeaders.Get("X-Getlicense-Timestamp"); got != strconv.FormatInt(ts, 10) {
		t.Errorf("X-GetLicense-Timestamp: want %d, got %s", ts, got)
	}
	if got := gotHeaders.Get("X-Getlicense-Signature-V2"); got != wantSigV2 {
		t.Errorf("X-GetLicense-Signature-V2: want %s, got %s", wantSigV2, got)
	}
	if got := gotHeaders.Get("X-Getlicense-Delivery-Id"); got != "per-attempt-delivery-id" {
		t.Errorf("X-GetLicense-Delivery-Id: want per-attempt-delivery-id, got %s", got)
	}
	// V2 prefix sanity
	if !strings.HasPrefix(gotHeaders.Get("X-Getlicense-Signature-V2"), "v1=") {
		t.Errorf("X-GetLicense-Signature-V2 must start with v1= scheme tag")
	}
}

// TestDoPost_TruncatesLargeResponseHeaders verifies the PR-A.1 (item
// 8) caps: a customer endpoint that returns many large response
// headers MUST NOT leak unbounded data into response_headers jsonb.
// We assert at-most maxStoredHeaderCount keys, and the value of any
// captured key is at most maxHeaderValueLen chars.
func TestDoPost_TruncatesLargeResponseHeaders(t *testing.T) {
	bigVal := strings.Repeat("x", maxHeaderValueLen*4) // 4 KiB

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Return many headers, most with a value larger than the
		// per-value cap. Header count exceeds maxStoredHeaderCount.
		for i := 0; i < maxStoredHeaderCount*2; i++ {
			w.Header().Set("X-Test-Header-"+strconv.Itoa(i), bigVal)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	res, err := doPost(t.Context(), client, srv.URL, "evt", "deliv", "sig", "v1=sig", time.Now().Unix(), []byte(`{}`))
	if err != nil {
		t.Fatalf("doPost returned error: %v", err)
	}

	if len(res.ResponseHeaders) == 0 {
		t.Fatal("expected response_headers to be populated")
	}
	var got map[string]string
	if err := json.Unmarshal(res.ResponseHeaders, &got); err != nil {
		t.Fatalf("response_headers is not valid JSON: %v", err)
	}
	if len(got) > maxStoredHeaderCount {
		t.Errorf("expected at most %d headers stored, got %d", maxStoredHeaderCount, len(got))
	}
	for k, v := range got {
		if len(k) > maxHeaderKeyLen {
			t.Errorf("header key %q exceeds maxHeaderKeyLen=%d", k, maxHeaderKeyLen)
		}
		if len(v) > maxHeaderValueLen {
			t.Errorf("header %q value len %d exceeds maxHeaderValueLen=%d", k, len(v), maxHeaderValueLen)
		}
	}
}
