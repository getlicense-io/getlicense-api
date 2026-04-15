package invitation

import (
	"context"
	"log/slog"
)

// Mailer sends invitation emails. Real SMTP/Postmark/Resend integration
// is out of Release 1 scope; the development implementation writes the
// link to slog so local testing is self-contained. Production swaps
// this for a real mailer at wiring time.
type Mailer interface {
	SendInvitation(ctx context.Context, to, kind, acceptURL string, meta map[string]string) error
}

// LogMailer is a dev/test mailer that logs the invitation details via
// slog at INFO level. It never fails. Real deployments replace it
// with an SMTP-backed implementation.
type LogMailer struct{}

func NewLogMailer() *LogMailer { return &LogMailer{} }

func (m *LogMailer) SendInvitation(_ context.Context, to, kind, acceptURL string, meta map[string]string) error {
	slog.Info("invitation email (dev)", "to", to, "kind", kind, "accept_url", acceptURL, "meta", meta)
	return nil
}
