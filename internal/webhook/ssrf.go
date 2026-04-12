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

	// Check hostname against private ranges.
	hostname := u.Hostname()
	if isPrivateHost(hostname) {
		return fmt.Errorf("webhook URL must not target private or loopback addresses")
	}

	return nil
}

func isPrivateHost(hostname string) bool {
	lower := strings.ToLower(hostname)
	if lower == "localhost" || lower == "" {
		return true
	}

	ip := net.ParseIP(hostname)
	if ip == nil {
		return false // not an IP literal — allow (DNS resolution checked at delivery time)
	}

	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
