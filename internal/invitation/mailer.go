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

// LogMailer is a dev/test mailer that logs the invitation details via
// slog at INFO level. It never fails.
//
// WARNING: This mailer logs the raw accept_url, which contains the
// invitation token. NEVER use this in production — any actor with
// log access can accept any in-flight invitation. Swap in an
// SMTP/Postmark/Resend implementation at wiring time.
type LogMailer struct{}

func NewLogMailer() *LogMailer { return &LogMailer{} }

func (m *LogMailer) SendInvitation(_ context.Context, to string, kind domain.InvitationKind, acceptURL string, meta map[string]string) error {
	slog.Info("invitation email (dev)", "to", to, "kind", string(kind), "accept_url", acceptURL, "meta", meta)
	return nil
}
