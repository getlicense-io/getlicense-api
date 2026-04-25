package invitation

import (
	"context"
	"log/slog"

	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Mailer sends invitation emails. Real SMTP/Postmark/Resend integration
// is out of Release 1 scope; the development implementation writes the
// link to slog so local testing is self-contained. Production swaps
// this for a real mailer at wiring time.
type Mailer interface {
	SendInvitation(ctx context.Context, to string, kind domain.InvitationKind, acceptURL string, meta map[string]string) error
}

// LogMailer writes the invitation accept_url to logs. **NEVER USE IN
// PRODUCTION** — the URL contains the invitation token, which is the
// credential for accepting the invitation. Any actor with log access
// can accept any in-flight invitation.
//
// SendInvitation panics if isProduction is true. The composition root
// is responsible for refusing to construct LogMailer in production via
// config (GETLICENSE_MAILER), but this defensive panic ensures that a
// programming error cannot silently leak tokens at runtime.
type LogMailer struct {
	isProduction bool
}

// NewLogMailer constructs a LogMailer. Pass isProduction so the
// runtime guard can panic if invoked outside development.
func NewLogMailer(isProduction bool) *LogMailer {
	return &LogMailer{isProduction: isProduction}
}

func (m *LogMailer) SendInvitation(_ context.Context, to string, kind domain.InvitationKind, acceptURL string, meta map[string]string) error {
	if m.isProduction {
		panic("invitation.LogMailer.SendInvitation called in production — refusing to log invitation accept_url. Set GETLICENSE_MAILER=noop or wire a real mailer.")
	}
	slog.Info("invitation email (dev)", "to", to, "kind", string(kind), "accept_url", acceptURL, "meta", meta)
	return nil
}

// NoopMailer accepts the call without delivering or logging the
// accept_url. Use as a default in production until a real mailer
// (SMTP/Postmark/SES) is wired. Records a metadata-only INFO log so
// operators can see invitation activity without the credential
// itself ending up in log aggregation.
type NoopMailer struct{}

func NewNoopMailer() *NoopMailer { return &NoopMailer{} }

func (m *NoopMailer) SendInvitation(_ context.Context, to string, kind domain.InvitationKind, _ string, meta map[string]string) error {
	slog.Info("invitation email (noop — no real mailer wired)", "to", to, "kind", string(kind), "meta", meta)
	return nil
}
