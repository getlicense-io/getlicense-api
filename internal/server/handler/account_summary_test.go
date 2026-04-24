package handler

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

func TestScrubGrantForReader_StripsLabelAndMetadataForGrantee(t *testing.T) {
	label := "vendor note"
	meta := json.RawMessage(`{"private":"x"}`)
	grantor := core.AccountID(uuid.MustParse("00000000-0000-0000-0000-000000000001"))
	grantee := core.AccountID(uuid.MustParse("00000000-0000-0000-0000-000000000002"))
	g := &domain.Grant{
		GrantorAccountID: grantor,
		GranteeAccountID: grantee,
		Label:            &label,
		Metadata:         meta,
	}
	scrubbed := scrubGrantForReader(g, grantee)
	assert.Nil(t, scrubbed.Label)
	assert.Empty(t, scrubbed.Metadata)
}

func TestScrubGrantForReader_GrantorSeesEverything(t *testing.T) {
	label := "vendor note"
	grantor := core.AccountID(uuid.MustParse("00000000-0000-0000-0000-000000000001"))
	grantee := core.AccountID(uuid.MustParse("00000000-0000-0000-0000-000000000002"))
	g := &domain.Grant{
		GrantorAccountID: grantor,
		GranteeAccountID: grantee,
		Label:            &label,
	}
	scrubbed := scrubGrantForReader(g, grantor)
	assert.Equal(t, &label, scrubbed.Label)
}

func TestScrubGrantForReader_NilInput(t *testing.T) {
	assert.Nil(t, scrubGrantForReader(nil, core.AccountID{}))
}

func TestScrubGrantsForReader_AppliesElementWise(t *testing.T) {
	label := "note"
	grantor := core.AccountID(uuid.MustParse("00000000-0000-0000-0000-000000000001"))
	grantee := core.AccountID(uuid.MustParse("00000000-0000-0000-0000-000000000002"))
	grants := []domain.Grant{
		{GrantorAccountID: grantor, GranteeAccountID: grantee, Label: &label},
		{GrantorAccountID: grantor, GranteeAccountID: grantee, Label: &label},
	}
	scrubbed := scrubGrantsForReader(grants, grantee)
	assert.Len(t, scrubbed, 2)
	assert.Nil(t, scrubbed[0].Label)
	assert.Nil(t, scrubbed[1].Label)
	// Original unchanged
	assert.Equal(t, &label, grants[0].Label)
}

func TestToAccountSummary_NilInput(t *testing.T) {
	assert.Nil(t, toAccountSummary(nil))
}

func TestToAccountSummary_ExactlyThreeFields(t *testing.T) {
	acc := &domain.Account{
		ID:   core.AccountID(uuid.New()),
		Name: "Acme",
		Slug: "acme",
		// CreatedAt is deliberately set — must NOT propagate
	}
	summary := toAccountSummary(acc)
	assert.Equal(t, acc.ID, summary.ID)
	assert.Equal(t, acc.Name, summary.Name)
	assert.Equal(t, acc.Slug, summary.Slug)
}
