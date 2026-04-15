package webhook

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateWebhookURL_RejectsPrivate(t *testing.T) {
	tests := []struct {
		url     string
		allowed bool
	}{
		{"https://example.com/webhook", true},
		{"https://api.stripe.com/hook", true},
		{"http://localhost/hook", false},
		{"http://127.0.0.1/hook", false},
		{"http://10.0.0.1/hook", false},
		{"http://172.16.0.1/hook", false},
		{"http://192.168.1.1/hook", false},
		{"http://[::1]/hook", false},
		{"http://0.0.0.0/hook", false},
		{"ftp://example.com/hook", false},             // non-HTTP scheme
		{"http://example.com/hook", false},             // HTTP not HTTPS in production
		{"https://169.254.169.254/metadata", false},    // AWS metadata
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := ValidateWebhookURL(tt.url, false) // production mode
			if tt.allowed {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidateWebhookURL_DevelopmentAllowsHTTP(t *testing.T) {
	assert.NoError(t, ValidateWebhookURL("http://localhost:3001/hook", true))
	assert.NoError(t, ValidateWebhookURL("http://127.0.0.1:8080/hook", true))
}

// F-004: cloud-metadata hostnames that are not IP literals must still
// be blocked at registration time via the explicit hostname list.
func TestValidateWebhookURL_BlocksMetadataHostnames(t *testing.T) {
	// Production mode.
	hosts := []string{
		"https://metadata.google.internal/",
		"https://METADATA.goog/compute",
		"https://169.254.169.254/latest/meta-data/",
	}
	for _, h := range hosts {
		t.Run(h, func(t *testing.T) {
			assert.Error(t, ValidateWebhookURL(h, false))
		})
	}
}

// F-004: the per-IP blocklist covers IMDS ranges outside RFC 1918 and
// link-local (Alibaba 100.100.100.200, Oracle 100.64.0.200), plus the
// IPv4-mapped IPv6 variant of loopback.
func TestIsBlockedIP_CoverageMatrix(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", "::ffff:127.0.0.1",
		"10.0.0.1", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", "169.254.0.1",
		"100.100.100.200", "100.64.0.200",
		"0.0.0.0",
	}
	for _, s := range blocked {
		t.Run("block/"+s, func(t *testing.T) {
			ip := net.ParseIP(s)
			require.NotNil(t, ip, "bad test fixture %s", s)
			assert.True(t, isBlockedIP(ip), "%s should be blocked", s)
		})
	}
	allowed := []string{
		"8.8.8.8", "1.1.1.1", "104.16.0.1", "2606:4700::1",
	}
	for _, s := range allowed {
		t.Run("allow/"+s, func(t *testing.T) {
			ip := net.ParseIP(s)
			require.NotNil(t, ip, "bad test fixture %s", s)
			assert.False(t, isBlockedIP(ip), "%s should be allowed", s)
		})
	}
}

// F-004: the delivery-time dialer refuses to connect to a blocked
// address, which is what catches DNS rebinding. We simulate rebinding
// by making a tiny loopback httptest server and then pointing a
// production-mode client at it — the Control callback should refuse
// the dial before the TCP handshake, without the server ever seeing
// the request.
func TestWebhookClient_ProdDialerRejectsLoopback(t *testing.T) {
	var received int
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		received++
	}))
	defer srv.Close()

	// In prod mode, dialing the loopback httptest server must fail.
	prodClient := newWebhookClient(false)
	resp, err := prodClient.Post(srv.URL, "application/json", strings.NewReader(`{}`))
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err, "prod dialer must refuse loopback")
	assert.Contains(t, err.Error(), "blocked")
	assert.Equal(t, 0, received, "server must not have received the request")
}

// F-004 dev-mode compatibility: in dev we intentionally allow local
// delivery so e2e scenarios can exercise the dispatcher against a
// localhost webhook receiver. Verify the same loopback server IS
// reachable via the dev client.
func TestWebhookClient_DevDialerAllowsLoopback(t *testing.T) {
	var received int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	devClient := newWebhookClient(true)
	resp, err := devClient.Post(srv.URL, "application/json", strings.NewReader(`{}`))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Equal(t, 1, received)
}

// F-004: redirect to a private IP must be refused via CheckRedirect.
// We stand up a public-facing httptest server that 302s to a known
// blocked URL string. In prod mode the client must refuse the second
// hop. We use the dev client for the TEST because httptest always
// binds loopback; the CheckRedirect function itself is the unit
// under test and we invoke it directly to sidestep the dev-mode bypass.
func TestWebhookClient_CheckRedirectRejectsPrivateTarget(t *testing.T) {
	// Build the client to access its CheckRedirect function.
	client := newWebhookClient(false) // prod mode
	require.NotNil(t, client.CheckRedirect)

	// Craft a fake redirect request and a via chain.
	u, _ := url.Parse("https://169.254.169.254/metadata")
	req := &http.Request{URL: u}
	err := client.CheckRedirect(req, []*http.Request{})
	require.Error(t, err, "redirect to IMDS must be refused")
}
