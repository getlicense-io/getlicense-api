package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
