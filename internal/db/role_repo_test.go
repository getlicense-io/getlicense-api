package db

import (
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/domain"
)

func TestRoleRepo_SatisfiesInterface(t *testing.T) {
	var _ domain.RoleRepository = (*RoleRepo)(nil)
}
