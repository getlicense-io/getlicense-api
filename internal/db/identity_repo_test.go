package db

import (
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/domain"
)

func TestIdentityRepo_SatisfiesInterface(t *testing.T) {
	var _ domain.IdentityRepository = (*IdentityRepo)(nil)
}
