package webhook

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateWebhookURL checks that a webhook URL is safe to deliver to.
// In production (isDev=false): requires HTTPS, rejects private/loopback IPs.
// In development (isDev=true): allows HTTP and localhost.
//
// This is the *registration-time* check. The *delivery-time* check
// runs inside the dialer's Control callback in deliver.go and catches
// DNS rebinding + hostnames that resolve to internal addresses. Both
// layers are needed because the hostname in the URL is not always an
// IP literal at registration time.
func ValidateWebhookURL(rawURL string, isDev bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if isDev {
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("URL scheme must be http or https")
		}
		return nil
	}

	// Production: HTTPS only.
	if u.Scheme != "https" {
		return fmt.Errorf("webhook URL must use HTTPS in production")
	}

	// Check hostname against private ranges. IP literals are rejected
	// immediately; hostnames fall through and get a second check at
	// dial time after DNS resolution (see deliver.go newWebhookClient).
	hostname := u.Hostname()
	if isBlockedHost(hostname) {
		return fmt.Errorf("webhook URL must not target private or loopback addresses")
	}

	return nil
}

// isBlockedHost returns true for any host whose resolved IP we refuse
// to dial in production. "localhost", the empty string, and any IP
// literal in a private / loopback / link-local / unspecified range
// are blocked. IMDS addresses that fall outside those ranges (Alibaba
// 100.100.100.200, Oracle 100.64.0.200) are blocked explicitly.
func isBlockedHost(hostname string) bool {
	lower := strings.ToLower(hostname)
	if lower == "localhost" || lower == "" {
		return true
	}

	// Explicit IMDS blocklist — these addresses are outside RFC 1918
	// and link-local ranges but are well-known cloud-metadata endpoints.
	switch lower {
	case "metadata.google.internal",
		"metadata.goog",
		"169.254.169.254",
		"100.100.100.200",
		"100.64.0.200",
		"169.254.169.250":
		return true
	}

	ip := net.ParseIP(hostname)
	if ip == nil {
		// Not an IP literal — the delivery-time dialer will re-check
		// every resolved IP before connecting. See newWebhookClient.
		return false
	}
	return isBlockedIP(ip)
}

// isBlockedIP returns true for a resolved IP that should never be the
// target of an outbound webhook. Covers loopback, RFC 1918 private,
// link-local, unspecified (0.0.0.0), and IPv4-mapped IPv6 variants of
// all of the above (net.IP handles mapping transparently).
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// Explicit IMDS IPv4 blocklist — cloud metadata addresses not
	// captured by IsPrivate / IsLinkLocal.
	switch ip.String() {
	case "169.254.169.254", "100.100.100.200", "100.64.0.200", "169.254.169.250":
		return true
	}
	return false
}
