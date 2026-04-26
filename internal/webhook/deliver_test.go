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

// TestBuildEnvelope_UsesDomainEventID: the public envelope `id` MUST
// equal the stable domain_event_id so consumers can dedupe duplicate
// fanouts. The webhook_event.id (per-attempt) lives on `delivery_id`.
func TestBuildEnvelope_UsesDomainEventID(t *testing.T) {
	domainID := core.NewDomainEventID()
	ev := &domain.WebhookEvent{
		ID:            core.NewWebhookEventID(),
		DomainEventID: domainID,
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

// TestBuildEnvelope_DeliveryIDPerAttempt locks in the invariant that
// DeliveryID is ALWAYS the per-attempt webhook_event.id. Two redeliver
// attempts of the same logical event must produce different DeliveryIDs
// while sharing the same envelope.id (= domain_event_id).
func TestBuildEnvelope_DeliveryIDPerAttempt(t *testing.T) {
	domainID := core.NewDomainEventID()
	ev1 := &domain.WebhookEvent{ID: core.NewWebhookEventID(), DomainEventID: domainID, Payload: json.RawMessage(`{}`)}
	ev2 := &domain.WebhookEvent{ID: core.NewWebhookEventID(), DomainEventID: domainID, Payload: json.RawMessage(`{}`)}

	env1 := buildEnvelope(ev1, ev1.Payload, time.Now().UTC())
	env2 := buildEnvelope(ev2, ev2.Payload, time.Now().UTC())

	if env1.ID != env2.ID {
		t.Errorf("redeliver envelopes must share id: got %s vs %s", env1.ID, env2.ID)
	}
	if env1.DeliveryID == env2.DeliveryID {
		t.Errorf("redeliver envelopes must have distinct delivery_id, both got %s", env1.DeliveryID)
	}
}

// TestDoPost_EmitsSignatureHeaders verifies the wire signature scheme:
// X-GetLicense-Signature = "v1=" + hex(hmac(secret, ts + "." + body)),
// alongside X-GetLicense-Timestamp and X-GetLicense-Delivery-Id.
func TestDoPost_EmitsSignatureHeaders(t *testing.T) {
	secret := []byte("test-secret-for-signatures")
	body := []byte(`{"id":"abc","event_type":"license.created"}`)
	ts := time.Now().UTC().Unix()
	wantSig := "v1=" + crypto.HMACSHA256Sign(secret, []byte(strconv.FormatInt(ts, 10)+"."+string(body)))

	var gotHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	res, err := doPost(t.Context(), client, srv.URL, "per-attempt-delivery-id", wantSig, ts, body)
	if err != nil {
		t.Fatalf("doPost returned error: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	if got := gotHeaders.Get("X-Getlicense-Timestamp"); got != strconv.FormatInt(ts, 10) {
		t.Errorf("X-GetLicense-Timestamp: want %d, got %s", ts, got)
	}
	if got := gotHeaders.Get("X-Getlicense-Signature"); got != wantSig {
		t.Errorf("X-GetLicense-Signature: want %s, got %s", wantSig, got)
	}
	if got := gotHeaders.Get("X-Getlicense-Delivery-Id"); got != "per-attempt-delivery-id" {
		t.Errorf("X-GetLicense-Delivery-Id: want per-attempt-delivery-id, got %s", got)
	}
	if !strings.HasPrefix(gotHeaders.Get("X-Getlicense-Signature"), "v1=") {
		t.Errorf("X-GetLicense-Signature must start with v1= scheme tag")
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
	res, err := doPost(t.Context(), client, srv.URL, "deliv", "v1=sig", time.Now().Unix(), []byte(`{}`))
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
