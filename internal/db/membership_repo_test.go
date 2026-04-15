package db

import (
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/domain"
)

func TestMembershipRepo_SatisfiesInterface(t *testing.T) {
	var _ domain.AccountMembershipRepository = (*MembershipRepo)(nil)
}
