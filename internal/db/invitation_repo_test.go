package db

import (
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/domain"
)

func TestInvitationRepo_SatisfiesInterface(t *testing.T) {
	var _ domain.InvitationRepository = (*InvitationRepo)(nil)
}
