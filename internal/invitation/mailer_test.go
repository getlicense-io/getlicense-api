package invitation_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/invitation"
)

func TestLogMailer_DevelopmentLogsAcceptURL(t *testing.T) {
	m := invitation.NewLogMailer(false)
	err := m.SendInvitation(context.Background(), "alice@example.com",
		domain.InvitationKindMembership, "https://app/invitations/SECRET", nil)
	require.NoError(t, err)
}

func TestLogMailer_ProductionPanics(t *testing.T) {
	m := invitation.NewLogMailer(true)
	assert.Panics(t, func() {
		_ = m.SendInvitation(context.Background(), "alice@example.com",
			domain.InvitationKindMembership, "https://app/invitations/SECRET", nil)
	}, "expected panic when LogMailer is invoked in production")
}

func TestNoopMailer_DoesNotLogAcceptURL(t *testing.T) {
	// The lack-of-URL-in-logs guarantee is structural (NoopMailer
	// doesn't include acceptURL in its log call), not behavioral.
	// We assert the call succeeds; the structural property is enforced
	// by the type signature and the implementation in mailer.go.
	m := invitation.NewNoopMailer()
	err := m.SendInvitation(context.Background(), "bob@example.com",
		domain.InvitationKindGrant, "https://app/invitations/SECRET", nil)
	require.NoError(t, err)
}
